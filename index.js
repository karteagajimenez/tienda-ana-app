require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Resend } = require('resend');
const session = require('express-session');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const resend = new Resend(process.env.RESEND_API_KEY);
const MySQLStore = require('express-mysql-session')(session);
const sessionStore = new MySQLStore({
  host: process.env.MYSQLHOST || process.env.DB_HOST || 'localhost',
  port: process.env.MYSQLPORT || process.env.DB_PORT || 3306,
  user: process.env.MYSQLUSER || process.env.DB_USER || 'root',
  password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD || '',
  database: process.env.MYSQLDATABASE || process.env.DB_NAME || 'tienda_ana'
});
const app = express();
app.set('trust proxy', 1);

app.use(session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,

    // ðŸ” Renovar la duraciÃ³n mientras el usuario siga activo
    rolling: true,

    cookie: {
        httpOnly: true,
        sameSite: 'lax',

        // Tiempo predeterminado
        maxAge: 1000 * 60 * 60 * 8
    }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ðŸ” PROTECCIÃ“N PARA SUPERADMIN Y ADMIN
function protegerAdmin(req, res, next) {

    if (!req.session.usuario) {
        return res.redirect('/login.html');
    }

    const rol = req.session.usuario.tipo_usuario;

    if (
        rol !== 'superadmin' &&
        rol !== 'admin'
    ) {
        return res
            .status(403)
            .send('Acceso no autorizado âŒ');
    }

    next();
}
// ðŸ” PROTECCIÃ“N PARA CLIENTE
function protegerCliente(req, res, next) {

    if (!req.session.usuario) {
        return res.redirect('/login.html');
    }

    if (req.session.usuario.tipo_usuario !== 'cliente') {
        return res
            .status(403)
            .send('Acceso no autorizado âŒ');
    }

    next();
}

// ðŸ” PROTEGER DASHBOARD
app.get('/dashboard.html', protegerAdmin, (req, res) => {

    res.sendFile(
        path.join(__dirname, 'public', 'dashboard.html')
    );
});
// ======================================================
// ðŸ” PROTEGER PÃGINAS DEL CLIENTE
// ======================================================

// ðŸ” PÃ¡gina principal del cliente
app.get('/client.html', protegerCliente, (req, res) => {

    res.sendFile(
        path.join(__dirname, 'public', 'client.html')
    );

});


// ðŸ” PÃ¡gina de archivos del cliente
app.get('/client_archived.html', protegerCliente, (req, res) => {

    res.sendFile(
        path.join(__dirname, 'public', 'client_archived.html')
    );

});
// ðŸ” PROTEGER PÃGINAS ADMINISTRATIVAS
const paginasAdmin = [
    'add_weight.html',
    'add_article.html',
    'articles.html',
    'edit_article.html',
    'details.html',
    'payment.html',
    'archived_orders.html'
];

paginasAdmin.forEach((pagina) => {

    app.get(`/${pagina}`, protegerAdmin, (req, res) => {

        res.sendFile(
            path.join(__dirname, 'public', pagina)
        );
    });
});
app.use(express.static(path.join(__dirname, 'public')));



// ðŸ”¹ CONEXIÃ“N MYSQL 
const conexion = mysql.createConnection({ 
    /*host: process.env.DB_HOST, 
    user: process.env.DB_USER, 
    password: process.env.DB_PASSWORD, 
    database: process.env.DB_NAME*/
    host: process.env.MYSQLHOST || process.env.DB_HOST || 'localhost',
    port: process.env.MYSQLPORT || process.env.DB_PORT || 3306,
    user: process.env.MYSQLUSER || process.env.DB_USER || 'root',
    password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD || '',
    database: process.env.MYSQLDATABASE || process.env.DB_NAME || 'tienda_ana'
});

conexion.connect(err => {
    if (err) {
        console.log('âŒ Error de conexiÃ³n:', err);
        return;
    }
    console.log('âœ… Conectado a MySQL');
});

// ðŸ”¥ CORREO
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

// ðŸ”¹ INICIO
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// ======================================================
// ðŸ” LÃMITE DE INTENTOS DE REGISTRO
// ======================================================

const registerLimiter = rateLimit({

    windowMs: 15 * 60 * 1000, // 15 minutos

    max: 5, // mÃ¡ximo 5 solicitudes

    standardHeaders: true,

    legacyHeaders: false,

    message:
        "Demasiados intentos de registro. Intente nuevamente en 15 minutos."

});



// ======================================================
// ðŸ”¹ REGISTRO
// ======================================================

app.post('/register', registerLimiter, async (req, res) => {

    try {

        const {
            nombre,
            apellido,
            telefono,
            correo,
            password,
            provincia,
            canton,
            distrito,
            direccion_exacta
        } = req.body;


        // ============================================
        // ðŸ” NORMALIZAR DATOS
        // ============================================

        const nombreNormalizado =
            String(nombre || '').trim();

        const apellidoNormalizado =
            String(apellido || '').trim();

        const telefonoNormalizado =
            String(telefono || '').trim();

        const correoNormalizado =
            String(correo || '')
                .trim()
                .toLowerCase();

        const provinciaNormalizada =
            String(provincia || '').trim();

        const cantonNormalizado =
            String(canton || '').trim();

        const distritoNormalizado =
            String(distrito || '').trim();

        const direccionNormalizada =
            String(direccion_exacta || '').trim();


        // ============================================
        // ðŸ” VALIDAR CAMPOS OBLIGATORIOS
        // ============================================

        if (
            !nombreNormalizado ||
            !apellidoNormalizado ||
            !telefonoNormalizado ||
            !correoNormalizado ||
            !provinciaNormalizada ||
            !cantonNormalizado ||
            !distritoNormalizado ||
            !direccionNormalizada
        ) {

            return res.status(400).send(
                "Complete todos los campos obligatorios."
            );

        }


        // ============================================
        // ðŸ” VALIDAR NOMBRE
        // SOLO LETRAS
        // ============================================

        const nombreValido =
            /^[A-Za-zÃÃ‰ÃÃ“ÃšÃ¡Ã©Ã­Ã³ÃºÃ‘Ã±ÃœÃ¼\s'-]+$/.test(
                nombreNormalizado
            );


        if (!nombreValido) {

            return res.status(400).send(
                "En el nombre solo se permiten letras."
            );

        }


        // ============================================
        // ðŸ” VALIDAR APELLIDO
        // SOLO LETRAS
        // ============================================

        const apellidoValido =
            /^[A-Za-zÃÃ‰ÃÃ“ÃšÃ¡Ã©Ã­Ã³ÃºÃ‘Ã±ÃœÃ¼\s'-]+$/.test(
                apellidoNormalizado
            );


        if (!apellidoValido) {

            return res.status(400).send(
                "En el apellido solo se permiten letras."
            );

        }


        // ============================================
        // ðŸ” VALIDAR LONGITUD NOMBRE Y APELLIDO
        // ============================================

        if (
            nombreNormalizado.length > 100 ||
            apellidoNormalizado.length > 100
        ) {

            return res.status(400).send(
                "El nombre o apellido es demasiado largo."
            );

        }


        // ============================================
        // ðŸ” VALIDAR TELÃ‰FONO
        // SOLO NÃšMEROS
        // NO SE LIMITA A 8 DÃGITOS
        // ============================================

        const telefonoValido =
            /^\d+$/.test(
                telefonoNormalizado
            );


        if (!telefonoValido) {

            return res.status(400).send(
                "En el telÃ©fono solo se permiten nÃºmeros."
            );

        }


        // Evitar nÃºmeros excesivamente largos

        if (telefonoNormalizado.length > 20) {

            return res.status(400).send(
                "El nÃºmero de telÃ©fono es demasiado largo."
            );

        }


        // ============================================
        // ðŸ” VALIDAR CORREO
        // ============================================

        const correoValido =
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
                correoNormalizado
            );


        if (!correoValido) {

            return res.status(400).send(
                "Ingrese un correo electrÃ³nico vÃ¡lido."
            );

        }


        // ============================================
        // ðŸ” VALIDAR PROVINCIA
        // ============================================

        const provinciasValidas = [

            "San JosÃ©",
            "Alajuela",
            "Cartago",
            "Heredia",
            "Guanacaste",
            "Puntarenas",
            "LimÃ³n"

        ];


        if (
            !provinciasValidas.includes(
                provinciaNormalizada
            )
        ) {

            return res.status(400).send(
                "Seleccione una provincia vÃ¡lida."
            );

        }


        // ============================================
        // ðŸ” VALIDAR CAMPOS DE DIRECCIÃ“N
        // ============================================

        if (
            cantonNormalizado.length > 100 ||
            distritoNormalizado.length > 100 ||
            direccionNormalizada.length > 255
        ) {

            return res.status(400).send(
                "Uno de los datos de direcciÃ³n es demasiado largo."
            );

        }


        // ============================================
        // ðŸ” VALIDAR CONTRASEÃ‘A
        // ============================================

        const passwordValido =
            typeof password === 'string' &&
            /^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(
                password
            );


        if (!passwordValido) {

            return res.status(400).send(
                "La contraseÃ±a debe tener mÃ­nimo 8 caracteres, al menos una letra y un nÃºmero."
            );

        }


        // ============================================
        // ðŸ” COMPROBAR SI EL CORREO YA EXISTE
        // ============================================

        conexion.query(
            `
            SELECT id_usuario
            FROM usuarios
            WHERE LOWER(TRIM(correo)) = ?
            LIMIT 1
            `,
            [
                correoNormalizado
            ],
            async (
                errorBuscar,
                resultados
            ) => {


                if (errorBuscar) {

                    console.log(
                        "âŒ Error verificando correo:",
                        errorBuscar
                    );

                    return res.status(500).send(
                        "Error âŒ"
                    );

                }


                // ============================================
                // ðŸ” CORREO YA REGISTRADO
                // ============================================

                if (resultados.length > 0) {

                    return res.status(409).send(
                        "Este correo ya estÃ¡ registrado. Inicie sesiÃ³n o recupere su contraseÃ±a."
                    );

                }


                try {


                    // ============================================
                    // ðŸ” ENCRIPTAR CONTRASEÃ‘A
                    // ============================================

                    const hash =
                        await bcrypt.hash(
                            password,
                            10
                        );


                    // ============================================
                    // ðŸ”¹ GUARDAR USUARIO
                    // ============================================

                    conexion.query(
                        `
                        INSERT INTO usuarios
                        (
                            nombre,
                            apellido,
                            telefono,
                            correo,
                            password,
                            tipo_usuario,
                            provincia,
                            canton,
                            distrito,
                            direccion_exacta
                        )
                        VALUES (?, ?, ?, ?, ?, 'cliente', ?, ?, ?, ?)
                        `,
                        [
                            nombreNormalizado,
                            apellidoNormalizado,
                            telefonoNormalizado,
                            correoNormalizado,
                            hash,
                            provinciaNormalizada,
                            cantonNormalizado,
                            distritoNormalizado,
                            direccionNormalizada
                        ],
                        (err) => {


                            if (err) {

                                console.log(
                                    "âŒ Error registrando usuario:",
                                    err
                                );

                                return res.status(500).send(
                                    "Error âŒ"
                                );

                            }


                            return res.send(`
                                <h2 style="text-align:center;color:green;">
                                    âœ… Registrado correctamente
                                </h2>
                            `);

                        }
                    );


                } catch (errorHash) {

                    console.log(
                        "âŒ Error preparando contraseÃ±a:",
                        errorHash
                    );

                    return res.status(500).send(
                        "Error âŒ"
                    );

                }

            }
        );


    } catch (error) {

        console.log(
            "âŒ Error en registro:",
            error
        );

        return res.status(500).send(
            "Error âŒ"
        );

    }

});
// ðŸ” LÃMITE DE INTENTOS DE LOGIN
const loginLimiter = rateLimit({

    windowMs: 15 * 60 * 1000, // 15 minutos

    max: 5, // mÃ¡ximo 5 intentos fallidos por cuenta

    standardHeaders: true,

    legacyHeaders: false,

    // ðŸ” Los inicios de sesiÃ³n correctos no cuentan
    skipSuccessfulRequests: true,

    // ðŸ” Cada correo tiene su propio contador de intentos
keyGenerator: (req) => {

    const correo =
        String(req.body?.correo || '')
            .trim()
            .toLowerCase();

    return correo || ipKeyGenerator(req.ip);

},

    message:
        "Demasiados intentos de inicio de sesiÃ³n para esta cuenta. Intente nuevamente en 15 minutos."

});

// ðŸ”¹ LOGIN
app.post('/login', loginLimiter, (req, res) => {

    const { correo, password } = req.body;

const correoNormalizado =
    String(correo || '')
        .trim()
        .toLowerCase();


conexion.query(
    "SELECT * FROM usuarios WHERE LOWER(TRIM(correo)) = ?",
    [correoNormalizado],
        async (err, results) => {

            if (err) {
                return res
                    .status(500)
                    .send("Error del servidor âŒ");
            }

            if (results.length === 0) {
                return res
                    .status(401)
                    .send("Usuario o contraseÃ±a incorrectos âŒ");
            }

            const usuario = results[0];

            

            const ok = await bcrypt.compare(
                password,
                usuario.password
            );

        

            if (!ok) {
                return res
                    .status(401)
                    .send("Usuario o contraseÃ±a incorrectos âŒ");
            }

            // ðŸ” CREAR UNA SESIÃ“N NUEVA DESPUÃ‰S DEL LOGIN
            req.session.regenerate((err) => {

                if (err) {
                    console.log(
                        "âŒ Error regenerando sesiÃ³n:",
                        err
                    );

                    return res
                        .status(500)
                        .send("No se pudo iniciar sesiÃ³n");
                }

                // ðŸ” GUARDAR DATOS DEL USUARIO EN LA NUEVA SESIÃ“N
                req.session.usuario = {
                    id_usuario: usuario.id_usuario,
                    tipo_usuario: usuario.tipo_usuario,
                    nombre: usuario.nombre
                };

// ======================================================
// â±ï¸ DURACIÃ“N DE SESIÃ“N SEGÃšN TIPO DE USUARIO
// ======================================================

// ðŸ‘¤ CLIENTE: 5 minutos
if (usuario.tipo_usuario === 'cliente') {

    req.session.cookie.maxAge =
        1000 * 60 * 5;

}

// ðŸ‘‘ ADMIN / SUPERADMIN: 8 horas
else if (
    usuario.tipo_usuario === 'admin' ||
    usuario.tipo_usuario === 'superadmin'
) {

    req.session.cookie.maxAge =
        1000 * 60 * 60 * 8;

}

                req.session.save((err) => {

                    if (err) {
                        console.log(
                            "âŒ Error guardando sesiÃ³n:",
                            err
                        );

                        return res
                            .status(500)
                            .send("No se pudo iniciar sesiÃ³n");
                    }

                    // ðŸ‘¤ CLIENTE
                    if (usuario.tipo_usuario === 'cliente') {

                        return res.redirect(
                            `/client.html?id=${usuario.id_usuario}`
                        );
                    }

                    // ðŸ‘‘ SUPERADMIN / ADMIN
                    if (
                        usuario.tipo_usuario === 'superadmin' ||
                        usuario.tipo_usuario === 'admin'
                    ) {

                        return res.redirect(
                            '/dashboard.html'
                        );
                    }

                    return res
                        .status(403)
                        .send("Acceso no autorizado");
                });
            });
        }
    );
});

// ðŸ” CERRAR SESIÃ“N
app.get('/logout', (req, res) => {

    req.session.destroy((err) => {

        if (err) {
            console.log('âŒ Error cerrando sesiÃ³n:', err);

            return res
                .status(500)
                .send('No se pudo cerrar la sesiÃ³n');
        }

        res.clearCookie('connect.sid');

        return res.redirect('/login.html');
    });
});



// ðŸ”¹ CLIENTES
app.get('/clientes', protegerAdmin, (req, res) => {

    conexion.query(`
        SELECT
            u.id_usuario,
            u.nombre,
            u.apellido,
            IFNULL(s.saldo_pendiente, 0) AS saldo_pendiente

        FROM usuarios u

        LEFT JOIN (
            SELECT
                f.id_usuario,
                SUM(
                    GREATEST(
                        f.total_productos
                        + ((f.peso_total / 1000) * 6000)
                        - IFNULL(a.total_abonado, 0),
                        0
                    )
                ) AS saldo_pendiente

            FROM (
                SELECT
                    p.id_usuario,

                    COALESCE(
                        p.grupo_compra,
                        CONCAT('pedido-', p.id_pedido)
                    ) AS factura,

                    SUM(IFNULL(p.total_precio, 0)) AS total_productos,
                    SUM(IFNULL(p.peso_gramos, 0)) AS peso_total

                FROM pedidos p

                GROUP BY
                    p.id_usuario,
                    COALESCE(
                        p.grupo_compra,
                        CONCAT('pedido-', p.id_pedido)
                    )
            ) f

            LEFT JOIN (
                SELECT
                    pa.id_usuario,

                    COALESCE(
                        pa.grupo_compra,
                        CONCAT('pedido-', pa.id_pedido)
                    ) AS factura,

                    SUM(a.monto_abono) AS total_abonado

                FROM abonos a

                INNER JOIN pedidos pa
                    ON pa.id_pedido = a.id_pedido

                GROUP BY
                    pa.id_usuario,
                    COALESCE(
                        pa.grupo_compra,
                        CONCAT('pedido-', pa.id_pedido)
                    )
            ) a
                ON a.id_usuario = f.id_usuario
                AND a.factura = f.factura

            GROUP BY
                f.id_usuario

        ) s
            ON s.id_usuario = u.id_usuario

        WHERE u.tipo_usuario = 'cliente'

        ORDER BY
            u.nombre ASC,
            u.apellido ASC

    `, (err, results) => {

        if (err) {

            console.log(
                "âŒ Error cargando clientes:",
                err
            );

            return res.json([]);
        }

        res.json(results);

    });

});

// ======================================================
// ðŸ”¹ CREAR CLIENTE MANUAL
// ======================================================

app.post(
    '/create-client',
    protegerAdmin,
    async (req, res) => {

        try{

            const {
                nombre,
                apellido,
                telefono,
                provincia,
                canton,
                distrito,
                direccion_exacta,
                correo,
                password
            } = req.body;


            // ======================================================
            // NORMALIZAR
            // ======================================================

            const nombreLimpio =
                String(nombre || '').trim();

            const apellidoLimpio =
                String(apellido || '').trim();

            const telefonoLimpio =
                String(telefono || '').trim();

            const provinciaLimpia =
                String(provincia || '').trim();

            const cantonLimpio =
                String(canton || '').trim();

            const distritoLimpio =
                String(distrito || '').trim();

            const direccionLimpia =
                String(direccion_exacta || '').trim();

            const correoLimpio =
                String(correo || '')
                    .trim()
                    .toLowerCase();

            const passwordLimpio =
                String(password || '');


            // ======================================================
            // CAMPOS OBLIGATORIOS
            // ======================================================

            if(
                !nombreLimpio ||
                !apellidoLimpio ||
                !telefonoLimpio ||
                !provinciaLimpia ||
                !cantonLimpio ||
                !distritoLimpio
            ){

                return res.status(400).json({
                    ok:false,
                    mensaje:
                        "Complete todos los campos obligatorios"
                });

            }


            // ======================================================
            // NOMBRE Y APELLIDO SOLO LETRAS
            // ======================================================

            const soloLetras =
                /^[A-Za-zÃÃ‰ÃÃ“ÃšÃ¡Ã©Ã­Ã³ÃºÃ‘Ã±ÃœÃ¼\s'-]+$/;


            if(
                !soloLetras.test(nombreLimpio)
            ){

                return res.status(400).json({
                    ok:false,
                    mensaje:
                        "En el nombre solo se permiten letras"
                });

            }


            if(
                !soloLetras.test(apellidoLimpio)
            ){

                return res.status(400).json({
                    ok:false,
                    mensaje:
                        "En el apellido solo se permiten letras"
                });

            }


            // ======================================================
            // TELÃ‰FONO SOLO NÃšMEROS
            // ======================================================

            if(
                !/^\d+$/.test(
                    telefonoLimpio
                )
            ){

                return res.status(400).json({
                    ok:false,
                    mensaje:
                        "En el telÃ©fono solo se permiten nÃºmeros"
                });

            }


            // ======================================================
            // CORREO Y CONTRASEÃ‘A
            // ======================================================

            const tieneCorreo =
                correoLimpio !== '';

            const tienePassword =
                passwordLimpio !== '';


            if(
                tieneCorreo &&
                !tienePassword
            ){

                return res.status(400).json({
                    ok:false,
                    mensaje:
                        "Si ingresa un correo tambiÃ©n debe ingresar una contraseÃ±a"
                });

            }


            if(
                !tieneCorreo &&
                tienePassword
            ){

                return res.status(400).json({
                    ok:false,
                    mensaje:
                        "Si ingresa una contraseÃ±a tambiÃ©n debe ingresar un correo"
                });

            }


            if(tieneCorreo){

                const correoValido =
                    /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

                if(
                    !correoValido.test(
                        correoLimpio
                    )
                ){

                    return res.status(400).json({
                        ok:false,
                        mensaje:
                            "Ingrese un correo electrÃ³nico vÃ¡lido"
                    });

                }

            }


            if(tienePassword){

                const passwordValido =
                    /^(?=.*[A-Za-z])(?=.*\d).{8,}$/;

                if(
                    !passwordValido.test(
                        passwordLimpio
                    )
                ){

                    return res.status(400).json({
                        ok:false,
                        mensaje:
                            "La contraseÃ±a debe tener mÃ­nimo 8 caracteres, al menos una letra y un nÃºmero"
                    });

                }

            }


            // ======================================================
            // SI HAY CORREO, VALIDAR DUPLICADO
            // ======================================================

            const continuarGuardado =
                async () => {

                    let hash = null;

                    if(tienePassword){

                        hash =
                            await bcrypt.hash(
                                passwordLimpio,
                                10
                            );

                    }


                    conexion.query(
                        `
                        INSERT INTO usuarios
                        (
                            nombre,
                            apellido,
                            telefono,
                            correo,
                            password,
                            tipo_usuario,
                            provincia,
                            canton,
                            distrito,
                            direccion_exacta
                        )
                        VALUES (?, ?, ?, ?, ?, 'cliente', ?, ?, ?, ?)
                        `,
                        [
                            nombreLimpio,
                            apellidoLimpio,
                            telefonoLimpio,
                            tieneCorreo
                                ? correoLimpio
                                : null,
                            hash,
                            provinciaLimpia,
                            cantonLimpio,
                            distritoLimpio,
                            direccionLimpia || null
                        ],
                        (err, result) => {

                            if(err){

                                console.log(
                                    "âŒ Error guardando cliente:",
                                    err
                                );

                                return res
                                    .status(500)
                                    .json({
                                        ok:false,
                                        mensaje:
                                            "No se pudo guardar el cliente"
                                    });

                            }


                            return res.json({
                                ok:true,
                                mensaje:
                                    "Cliente guardado exitosamente",
                                id_usuario:
                                    result.insertId
                            });

                        }
                    );

                };


            if(tieneCorreo){

                conexion.query(
                    `
                    SELECT id_usuario
                    FROM usuarios
                    WHERE LOWER(TRIM(correo)) = ?
                    LIMIT 1
                    `,
                    [
                        correoLimpio
                    ],
                    async (
                        err,
                        resultados
                    ) => {

                        if(err){

                            console.log(
                                "âŒ Error verificando correo:",
                                err
                            );

                            return res
                                .status(500)
                                .json({
                                    ok:false,
                                    mensaje:
                                        "No se pudo verificar el correo"
                                });

                        }


                        if(
                            resultados.length > 0
                        ){

                            return res
                                .status(409)
                                .json({
                                    ok:false,
                                    mensaje:
                                        "Este correo ya estÃ¡ registrado"
                                });

                        }


                        await continuarGuardado();

                    }
                );

            }else{

                await continuarGuardado();

            }


        }catch(error){

            console.log(
                "âŒ Error creando cliente:",
                error
            );

            return res
                .status(500)
                .json({
                    ok:false,
                    mensaje:
                        "No se pudo guardar el cliente"
                });

        }

    }
);

// ======================================================
// ðŸ”¹ ACTUALIZAR CLIENTE
// ======================================================

app.post(
    '/update-client',
    protegerAdmin,
    async (req, res) => {

        try{

            const {
                id_usuario,
                nombre,
                apellido,
                telefono,
                provincia,
                canton,
                distrito,
                direccion_exacta,
                correo,
                password
            } = req.body;


            const idUsuario =
                Number(id_usuario);

            const nombreLimpio =
                String(nombre || '').trim();

            const apellidoLimpio =
                String(apellido || '').trim();

            const telefonoLimpio =
                String(telefono || '').trim();

            const provinciaLimpia =
                String(provincia || '').trim();

            const cantonLimpio =
                String(canton || '').trim();

            const distritoLimpio =
                String(distrito || '').trim();

            const direccionLimpia =
                String(direccion_exacta || '').trim();

            const correoLimpio =
                String(correo || '')
                    .trim()
                    .toLowerCase();

            const passwordLimpio =
                String(password || '');


            // ======================================================
            // VALIDAR CLIENTE
            // ======================================================

            if(
                !Number.isInteger(idUsuario) ||
                idUsuario <= 0
            ){

                return res.status(400).json({
                    ok:false,
                    mensaje:
                        "Seleccione un cliente vÃ¡lido"
                });

            }


            // ======================================================
            // CAMPOS OBLIGATORIOS
            // ======================================================

            if(
                !nombreLimpio ||
                !apellidoLimpio ||
                !telefonoLimpio ||
                !provinciaLimpia ||
                !cantonLimpio ||
                !distritoLimpio
            ){

                return res.status(400).json({
                    ok:false,
                    mensaje:
                        "Complete todos los campos obligatorios"
                });

            }


            // ======================================================
            // NOMBRE Y APELLIDO
            // ======================================================

            const soloLetras =
                /^[A-Za-zÃÃ‰ÃÃ“ÃšÃ¡Ã©Ã­Ã³ÃºÃ‘Ã±ÃœÃ¼\s'-]+$/;


            if(
                !soloLetras.test(
                    nombreLimpio
                )
            ){

                return res.status(400).json({
                    ok:false,
                    mensaje:
                        "En el nombre solo se permiten letras"
                });

            }


            if(
                !soloLetras.test(
                    apellidoLimpio
                )
            ){

                return res.status(400).json({
                    ok:false,
                    mensaje:
                        "En el apellido solo se permiten letras"
                });

            }


            // ======================================================
            // TELÃ‰FONO
            // ======================================================

            if(
                !/^\d+$/.test(
                    telefonoLimpio
                )
            ){

                return res.status(400).json({
                    ok:false,
                    mensaje:
                        "En el telÃ©fono solo se permiten nÃºmeros"
                });

            }


            // ======================================================
            // CORREO
            // ======================================================

            const tieneCorreo =
                correoLimpio !== '';

            const tienePassword =
                passwordLimpio !== '';


            if(tieneCorreo){

                const correoValido =
                    /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

                if(
                    !correoValido.test(
                        correoLimpio
                    )
                ){

                    return res.status(400).json({
                        ok:false,
                        mensaje:
                            "Ingrese un correo electrÃ³nico vÃ¡lido"
                    });

                }

            }


            // ======================================================
            // NUEVA CONTRASEÃ‘A
            // ======================================================

            if(tienePassword){

                const passwordValido =
                    /^(?=.*[A-Za-z])(?=.*\d).{8,}$/;

                if(
                    !passwordValido.test(
                        passwordLimpio
                    )
                ){

                    return res.status(400).json({
                        ok:false,
                        mensaje:
                            "La nueva contraseÃ±a debe tener mÃ­nimo 8 caracteres, al menos una letra y un nÃºmero"
                    });

                }

            }


            // ======================================================
            // BUSCAR CLIENTE ACTUAL
            // ======================================================

            conexion.query(
                `
                SELECT
                    id_usuario,
                    correo,
                    password
                FROM usuarios
                WHERE id_usuario = ?
                AND tipo_usuario = 'cliente'
                LIMIT 1
                `,
                [
                    idUsuario
                ],
                async (
                    errBuscar,
                    resultadosCliente
                ) => {

                    if(errBuscar){

                        console.log(
                            "âŒ Error buscando cliente:",
                            errBuscar
                        );

                        return res
                            .status(500)
                            .json({
                                ok:false,
                                mensaje:
                                    "No se pudo buscar el cliente"
                            });

                    }


                    if(
                        resultadosCliente.length === 0
                    ){

                        return res
                            .status(404)
                            .json({
                                ok:false,
                                mensaje:
                                    "Cliente no encontrado"
                            });

                    }


                    const clienteActual =
                        resultadosCliente[0];


                    // ==============================================
                    // REGLA CORREO / CONTRASEÃ‘A
                    // ==============================================

                    const teniaPassword =
                        !!clienteActual.password;


                    /*
                        Si el cliente todavÃ­a NO tenÃ­a acceso:
                        correo y contraseÃ±a deben agregarse juntos.
                    */

                    if(
                        !teniaPassword &&
                        tieneCorreo &&
                        !tienePassword
                    ){

                        return res
                            .status(400)
                            .json({
                                ok:false,
                                mensaje:
                                    "Para activar el acceso debe ingresar correo y contraseÃ±a"
                            });

                    }


                    if(
                        !teniaPassword &&
                        !tieneCorreo &&
                        tienePassword
                    ){

                        return res
                            .status(400)
                            .json({
                                ok:false,
                                mensaje:
                                    "Para activar el acceso debe ingresar correo y contraseÃ±a"
                            });

                    }


                    /*
                        Si el cliente ya tenÃ­a acceso:
                        puede cambiar datos y dejar Nueva contraseÃ±a vacÃ­a.
                    */

                    if(
                        teniaPassword &&
                        !tieneCorreo
                    ){

                        return res
                            .status(400)
                            .json({
                                ok:false,
                                mensaje:
                                    "Este cliente ya tiene acceso y debe conservar un correo"
                            });

                    }


                    // ==============================================
                    // VALIDAR CORREO DUPLICADO
                    // ==============================================

                    const continuarActualizacion =
                        async () => {

                            let nuevoHash =
                                clienteActual.password;

                            if(tienePassword){

                                nuevoHash =
                                    await bcrypt.hash(
                                        passwordLimpio,
                                        10
                                    );

                            }


                            conexion.query(
                                `
                                UPDATE usuarios
                                SET
                                    nombre = ?,
                                    apellido = ?,
                                    telefono = ?,
                                    correo = ?,
                                    password = ?,
                                    provincia = ?,
                                    canton = ?,
                                    distrito = ?,
                                    direccion_exacta = ?
                                WHERE id_usuario = ?
                                AND tipo_usuario = 'cliente'
                                `,
                                [
                                    nombreLimpio,
                                    apellidoLimpio,
                                    telefonoLimpio,
                                    tieneCorreo
                                        ? correoLimpio
                                        : null,
                                    nuevoHash || null,
                                    provinciaLimpia,
                                    cantonLimpio,
                                    distritoLimpio,
                                    direccionLimpia || null,
                                    idUsuario
                                ],
                                (
                                    errActualizar,
                                    resultado
                                ) => {

                                    if(errActualizar){

                                        console.log(
                                            "âŒ Error actualizando cliente:",
                                            errActualizar
                                        );

                                        return res
                                            .status(500)
                                            .json({
                                                ok:false,
                                                mensaje:
                                                    "No se pudo actualizar el cliente"
                                            });

                                    }


                                    if(
                                        resultado.affectedRows === 0
                                    ){

                                        return res
                                            .status(404)
                                            .json({
                                                ok:false,
                                                mensaje:
                                                    "Cliente no encontrado"
                                            });

                                    }


                                    return res.json({
                                        ok:true,
                                        mensaje:
                                            "Cliente actualizado correctamente"
                                    });

                                }
                            );

                        };


                    if(tieneCorreo){

                        conexion.query(
                            `
                            SELECT id_usuario
                            FROM usuarios
                            WHERE LOWER(TRIM(correo)) = ?
                            AND id_usuario <> ?
                            LIMIT 1
                            `,
                            [
                                correoLimpio,
                                idUsuario
                            ],
                            async (
                                errCorreo,
                                resultadosCorreo
                            ) => {

                                if(errCorreo){

                                    console.log(
                                        "âŒ Error verificando correo:",
                                        errCorreo
                                    );

                                    return res
                                        .status(500)
                                        .json({
                                            ok:false,
                                            mensaje:
                                                "No se pudo verificar el correo"
                                        });

                                }


                                if(
                                    resultadosCorreo.length > 0
                                ){

                                    return res
                                        .status(409)
                                        .json({
                                            ok:false,
                                            mensaje:
                                                "Este correo ya estÃ¡ registrado"
                                        });

                                }


                                await continuarActualizacion();

                            }
                        );

                    }else{

                        await continuarActualizacion();

                    }

                }
            );


        }catch(error){

            console.log(
                "âŒ Error actualizando cliente:",
                error
            );

            return res
                .status(500)
                .json({
                    ok:false,
                    mensaje:
                        "No se pudo actualizar el cliente"
                });

        }

    }
);
// ======================================================
// ðŸ”´ ELIMINAR CLIENTE COMPLETAMENTE
// ======================================================

app.post(
    '/delete-client',
    protegerAdmin,
    (req, res) => {

        const idUsuario =
            Number(
                req.body.id_usuario
            );


        // ======================================================
        // VALIDAR CLIENTE
        // ======================================================

        if(
            !Number.isInteger(idUsuario) ||
            idUsuario <= 0
        ){

            return res
                .status(400)
                .json({
                    ok: false,
                    mensaje:
                        "Cliente invÃ¡lido"
                });

        }


        // ======================================================
        // INICIAR TRANSACCIÃ“N
        // ======================================================

        conexion.beginTransaction(
            (errorTransaccion) => {

                if(errorTransaccion){

                    console.log(
                        "âŒ Error iniciando eliminaciÃ³n del cliente:",
                        errorTransaccion
                    );

                    return res
                        .status(500)
                        .json({
                            ok: false,
                            mensaje:
                                "No se pudo iniciar la eliminaciÃ³n"
                        });

                }


                // ======================================================
                // COMPROBAR QUE EL CLIENTE EXISTE
                // ======================================================

                conexion.query(
                    `
                    SELECT id_usuario
                    FROM usuarios
                    WHERE id_usuario = ?
                    AND tipo_usuario = 'cliente'
                    LIMIT 1
                    `,
                    [
                        idUsuario
                    ],
                    (
                        errorCliente,
                        clientes
                    ) => {

                        if(errorCliente){

                            return conexion.rollback(
                                () => {

                                    console.log(
                                        "âŒ Error buscando cliente:",
                                        errorCliente
                                    );

                                    return res
                                        .status(500)
                                        .json({
                                            ok: false,
                                            mensaje:
                                                "No se pudo buscar el cliente"
                                        });

                                }
                            );

                        }


                        if(
                            !clientes ||
                            clientes.length === 0
                        ){

                            return conexion.rollback(
                                () => {

                                    return res
                                        .status(404)
                                        .json({
                                            ok: false,
                                            mensaje:
                                                "Cliente no encontrado"
                                        });

                                }
                            );

                        }


                        // ======================================================
                        // BUSCAR PEDIDOS Y GRUPOS DEL CLIENTE
                        // ======================================================

                        conexion.query(
                            `
                            SELECT
                                id_pedido,
                                grupo_compra
                            FROM pedidos
                            WHERE id_usuario = ?
                            `,
                            [
                                idUsuario
                            ],
                            (
                                errorPedidos,
                                pedidos
                            ) => {

                                if(errorPedidos){

                                    return conexion.rollback(
                                        () => {

                                            console.log(
                                                "âŒ Error buscando pedidos del cliente:",
                                                errorPedidos
                                            );

                                            return res
                                                .status(500)
                                                .json({
                                                    ok: false,
                                                    mensaje:
                                                        "No se pudieron buscar los pedidos del cliente"
                                                });

                                        }
                                    );

                                }


                                const idsPedidos =
                                    pedidos.map(
                                        pedido =>
                                            pedido.id_pedido
                                    );


                                const idsGrupos =
                                    [
                                        ...new Set(
                                            pedidos
                                                .map(
                                                    pedido =>
                                                        Number(
                                                            pedido.grupo_compra
                                                        )
                                                )
                                                .filter(
                                                    idGrupo =>
                                                        Number.isInteger(
                                                            idGrupo
                                                        ) &&
                                                        idGrupo > 0
                                                )
                                        )
                                    ];


                                // ======================================================
                                // ELIMINAR PEDIDOS
                                // ======================================================

                                const eliminarPedidos =
                                    () => {

                                        conexion.query(
                                            `
                                            DELETE FROM pedidos
                                            WHERE id_usuario = ?
                                            `,
                                            [
                                                idUsuario
                                            ],
                                            (
                                                errorEliminarPedidos
                                            ) => {

                                                if(
                                                    errorEliminarPedidos
                                                ){

                                                    return conexion.rollback(
                                                        () => {

                                                            console.log(
                                                                "âŒ Error eliminando pedidos:",
                                                                errorEliminarPedidos
                                                            );

                                                            return res
                                                                .status(500)
                                                                .json({
                                                                    ok: false,
                                                                    mensaje:
                                                                        "No se pudieron eliminar los pedidos del cliente"
                                                                });

                                                        }
                                                    );

                                                }


                                                eliminarGrupos();

                                            }
                                        );

                                    };


                                // ======================================================
                                // ELIMINAR GRUPOS QUE QUEDARON VACÃOS
                                // ======================================================

                                const eliminarGrupos =
                                    () => {

                                        if(
                                            idsGrupos.length === 0
                                        ){

                                            return eliminarUsuario();

                                        }


                                        conexion.query(
                                            `
                                            DELETE g
                                            FROM grupos_compra g

                                            LEFT JOIN pedidos p
                                                ON p.grupo_compra =
                                                   g.id_grupo

                                            WHERE g.id_grupo IN (?)
                                            AND p.id_pedido IS NULL
                                            `,
                                            [
                                                idsGrupos
                                            ],
                                            (
                                                errorGrupos
                                            ) => {

                                                if(errorGrupos){

                                                    return conexion.rollback(
                                                        () => {

                                                            console.log(
                                                                "âŒ Error eliminando grupos:",
                                                                errorGrupos
                                                            );

                                                            return res
                                                                .status(500)
                                                                .json({
                                                                    ok: false,
                                                                    mensaje:
                                                                        "No se pudieron eliminar las facturas del cliente"
                                                                });

                                                        }
                                                    );

                                                }


                                                eliminarUsuario();

                                            }
                                        );

                                    };


                                // ======================================================
                                // ELIMINAR USUARIO
                                // ======================================================

                                const eliminarUsuario =
                                    () => {

                                        conexion.query(
                                            `
                                            DELETE FROM usuarios
                                            WHERE id_usuario = ?
                                            AND tipo_usuario = 'cliente'
                                            `,
                                            [
                                                idUsuario
                                            ],
                                            (
                                                errorUsuario,
                                                resultadoUsuario
                                            ) => {

                                                if(errorUsuario){

                                                    return conexion.rollback(
                                                        () => {

                                                            console.log(
                                                                "âŒ Error eliminando cliente:",
                                                                errorUsuario
                                                            );

                                                            return res
                                                                .status(500)
                                                                .json({
                                                                    ok: false,
                                                                    mensaje:
                                                                        "No se pudo eliminar el cliente"
                                                                });

                                                        }
                                                    );

                                                }


                                                if(
                                                    resultadoUsuario
                                                        .affectedRows === 0
                                                ){

                                                    return conexion.rollback(
                                                        () => {

                                                            return res
                                                                .status(404)
                                                                .json({
                                                                    ok: false,
                                                                    mensaje:
                                                                        "Cliente no encontrado"
                                                                });

                                                        }
                                                    );

                                                }


                                                // ======================================================
                                                // CONFIRMAR TODO
                                                // ======================================================

                                                conexion.commit(
                                                    (
                                                        errorCommit
                                                    ) => {

                                                        if(
                                                            errorCommit
                                                        ){

                                                            return conexion.rollback(
                                                                () => {

                                                                    console.log(
                                                                        "âŒ Error confirmando eliminaciÃ³n:",
                                                                        errorCommit
                                                                    );

                                                                    return res
                                                                        .status(500)
                                                                        .json({
                                                                            ok: false,
                                                                            mensaje:
                                                                                "No se pudo completar la eliminaciÃ³n"
                                                                        });

                                                                }
                                                            );

                                                        }


                                                        return res.json({
                                                            ok: true,
                                                            mensaje:
                                                                "Cliente eliminado completamente"
                                                        });

                                                    }
                                                );

                                            }
                                        );

                                    };


                                // ======================================================
                                // ELIMINAR ABONOS PRIMERO
                                // ======================================================

                                if(
                                    idsPedidos.length > 0
                                ){

                                    conexion.query(
                                        `
                                        DELETE FROM abonos
                                        WHERE id_pedido IN (?)
                                        `,
                                        [
                                            idsPedidos
                                        ],
                                        (
                                            errorAbonos
                                        ) => {

                                            if(errorAbonos){

                                                return conexion.rollback(
                                                    () => {

                                                        console.log(
                                                            "âŒ Error eliminando abonos:",
                                                            errorAbonos
                                                        );

                                                        return res
                                                            .status(500)
                                                            .json({
                                                                ok: false,
                                                                mensaje:
                                                                    "No se pudieron eliminar los abonos del cliente"
                                                            });

                                                    }
                                                );

                                            }


                                            eliminarPedidos();

                                        }
                                    );

                                }else{

                                    eliminarPedidos();

                                }

                            }
                        );

                    }
                );

            }
        );

    }
);
// ðŸ”¹ ARTÃCULOS
// Carga los artÃ­culos guardados en el catÃ¡logo.
app.get('/articulos', protegerAdmin, (req, res) => {

    conexion.query(`
        SELECT
            id_articulo,
            nombre,
            tasa,
            descripcion
        FROM articulos
        ORDER BY nombre ASC
    `, (err, results) => {

        if (err) {
            console.log("âŒ Error cargando artÃ­culos:", err);
            return res.json([]);
        }

        res.json(results);

    });

});
// ======================================================
// ðŸ‘¤ ACTUALIZAR PERFIL DEL CLIENTE
// ======================================================

app.post(
    '/update-profile',
    protegerCliente,
    async (req, res) => {

        try {

            const idUsuario =
                Number(
                    req.session.usuario.id_usuario
                );


            const {
                nombre,
                apellido,
                telefono,
                correo,
                provincia,
                canton,
                distrito,
                direccion_exacta,
                passwordActual,
                passwordNueva,
                passwordConfirmar
            } = req.body;


            // ======================================================
            // NORMALIZAR DATOS
            // ======================================================

            const nombreLimpio =
                String(nombre || '').trim();

            const apellidoLimpio =
                String(apellido || '').trim();

            const telefonoLimpio =
                String(telefono || '').trim();

            const correoLimpio =
                String(correo || '')
                    .trim()
                    .toLowerCase();

            const provinciaLimpia =
                String(provincia || '').trim();

            const cantonLimpio =
                String(canton || '').trim();

            const distritoLimpio =
                String(distrito || '').trim();

            const direccionLimpia =
                String(
                    direccion_exacta || ''
                ).trim();

            const passwordActualLimpio =
                String(passwordActual || '');

            const passwordNuevaLimpio =
                String(passwordNueva || '');

            const passwordConfirmarLimpio =
                String(passwordConfirmar || '');


            // ======================================================
            // VALIDAR CAMPOS OBLIGATORIOS
            // ======================================================

            if (
                !nombreLimpio ||
                !apellidoLimpio ||
                !telefonoLimpio ||
                !correoLimpio ||
                !provinciaLimpia ||
                !cantonLimpio ||
                !distritoLimpio
            ) {

                return res
                    .status(400)
                    .json({
                        ok: false,
                        mensaje:
                            "Complete todos los campos obligatorios"
                    });

            }


            // ======================================================
            // NOMBRE Y APELLIDO SOLO LETRAS
            // ======================================================

            const soloLetras =
                /^[A-Za-zÃÃ‰ÃÃ“ÃšÃ¡Ã©Ã­Ã³ÃºÃ‘Ã±ÃœÃ¼\s'-]+$/;


            if (
                !soloLetras.test(
                    nombreLimpio
                )
            ) {

                return res
                    .status(400)
                    .json({
                        ok: false,
                        mensaje:
                            "En el nombre solo se permiten letras"
                    });

            }


            if (
                !soloLetras.test(
                    apellidoLimpio
                )
            ) {

                return res
                    .status(400)
                    .json({
                        ok: false,
                        mensaje:
                            "En el apellido solo se permiten letras"
                    });

            }


            // ======================================================
            // TELÃ‰FONO SOLO NÃšMEROS
            // ======================================================

            if (
                !/^\d+$/.test(
                    telefonoLimpio
                )
            ) {

                return res
                    .status(400)
                    .json({
                        ok: false,
                        mensaje:
                            "En el telÃ©fono solo se permiten nÃºmeros"
                    });

            }


            // ======================================================
            // CORREO
            // ======================================================

            const correoValido =
                /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


            if (
                !correoValido.test(
                    correoLimpio
                )
            ) {

                return res
                    .status(400)
                    .json({
                        ok: false,
                        mensaje:
                            "Ingrese un correo electrÃ³nico vÃ¡lido"
                    });

            }


            // ======================================================
            // PROVINCIA
            // ======================================================

            const provinciasValidas = [
                "San JosÃ©",
                "Alajuela",
                "Cartago",
                "Heredia",
                "Guanacaste",
                "Puntarenas",
                "LimÃ³n"
            ];


            if (
                !provinciasValidas.includes(
                    provinciaLimpia
                )
            ) {

                return res
                    .status(400)
                    .json({
                        ok: false,
                        mensaje:
                            "Seleccione una provincia vÃ¡lida"
                    });

            }


            // ======================================================
            // NUEVA CONTRASEÃ‘A
            // ======================================================

            if (passwordNuevaLimpio) {

                const passwordValido =
                    /^(?=.*[A-Za-z])(?=.*\d).{8,}$/;


                if (
                    !passwordValido.test(
                        passwordNuevaLimpio
                    )
                ) {

                    return res
                        .status(400)
                        .json({
                            ok: false,
                            mensaje:
                                "La nueva contraseÃ±a debe tener mÃ­nimo 8 caracteres, al menos una letra y un nÃºmero"
                        });

                }


                if (
                    passwordNuevaLimpio !==
                    passwordConfirmarLimpio
                ) {

                    return res
                        .status(400)
                        .json({
                            ok: false,
                            mensaje:
                                "Las nuevas contraseÃ±as no coinciden"
                        });

                }

            }


            // ======================================================
            // BUSCAR DATOS ACTUALES DEL CLIENTE
            // ======================================================

            conexion.query(
                `
                SELECT
                    id_usuario,
                    correo,
                    password,
                    ultimo_cambio_password
                FROM usuarios
                WHERE id_usuario = ?
                AND tipo_usuario = 'cliente'
                LIMIT 1
                `,
                [
                    idUsuario
                ],
                async (
                    errorBuscar,
                    resultados
                ) => {

                    if (errorBuscar) {

                        console.log(
                            "âŒ Error buscando perfil:",
                            errorBuscar
                        );

                        return res
                            .status(500)
                            .json({
                                ok: false,
                                mensaje:
                                    "No se pudo cargar el perfil"
                            });

                    }


                    if (
                        resultados.length === 0
                    ) {

                        return res
                            .status(404)
                            .json({
                                ok: false,
                                mensaje:
                                    "Cliente no encontrado"
                            });

                    }


                    const usuarioActual =
                        resultados[0];


                    const correoActual =
                        String(
                            usuarioActual.correo || ''
                        )
                        .trim()
                        .toLowerCase();


                    const cambioCorreo =
                        correoLimpio !==
                        correoActual;


                    const cambioPassword =
                        passwordNuevaLimpio !== '';


                    // ======================================================
                    // SI CAMBIA CORREO, DEBE CAMBIAR CONTRASEÃ‘A
                    // ======================================================

                    if (
                        cambioCorreo &&
                        !cambioPassword
                    ) {

                        return res
                            .status(400)
                            .json({
                                ok: false,
                                mensaje:
                                    "Si cambia el correo debe establecer una nueva contraseÃ±a"
                            });

                    }


                    // ======================================================
                    // SI CAMBIA CORREO O CONTRASEÃ‘A,
                    // PEDIR CONTRASEÃ‘A ACTUAL
                    // ======================================================

                    if (
                        (
                            cambioCorreo ||
                            cambioPassword
                        ) &&
                        !passwordActualLimpio
                    ) {

                        return res
                            .status(400)
                            .json({
                                ok: false,
                                mensaje:
                                    "Ingrese su contraseÃ±a actual"
                            });

                    }


                    // ======================================================
                    // VERIFICAR CONTRASEÃ‘A ACTUAL
                    // ======================================================

                    if (
                        cambioCorreo ||
                        cambioPassword
                    ) {

                        const passwordCorrecta =
                            await bcrypt.compare(
                                passwordActualLimpio,
                                usuarioActual.password
                            );


                        if (!passwordCorrecta) {

                            return res
                                .status(401)
                                .json({
                                    ok: false,
                                    mensaje:
                                        "La contraseÃ±a actual es incorrecta"
                                });

                        }

                    }


                    // ======================================================
                    // LÃMITE DE CAMBIO DE CONTRASEÃ‘A:
                    // 1 CADA 24 HORAS
                    // ======================================================

                    if (
                        cambioPassword &&
                        usuarioActual
                            .ultimo_cambio_password
                    ) {

                        const ultimoCambio =
                            new Date(
                                usuarioActual
                                    .ultimo_cambio_password
                            );

                        const ahora =
                            new Date();

                        const diferencia =
                            ahora.getTime() -
                            ultimoCambio.getTime();

                        const veinticuatroHoras =
                            24 * 60 * 60 * 1000;


                        if (
                            diferencia <
                            veinticuatroHoras
                        ) {

                            const restante =
                                veinticuatroHoras -
                                diferencia;

                            const horasRestantes =
                                Math.ceil(
                                    restante /
                                    (
                                        60 *
                                        60 *
                                        1000
                                    )
                                );


                            return res
                                .status(429)
                                .json({
                                    ok: false,
                                    mensaje:
                                        `Solo puede cambiar la contraseÃ±a una vez cada 24 horas. Intente nuevamente en aproximadamente ${horasRestantes} hora(s).`
                                });

                        }

                    }


                    // ======================================================
                    // VERIFICAR QUE EL NUEVO CORREO
                    // NO PERTENEZCA A OTRO USUARIO
                    // ======================================================

                    conexion.query(
                        `
                        SELECT id_usuario
                        FROM usuarios
                        WHERE LOWER(TRIM(correo)) = ?
                        AND id_usuario <> ?
                        LIMIT 1
                        `,
                        [
                            correoLimpio,
                            idUsuario
                        ],
                        async (
                            errorCorreo,
                            correos
                        ) => {

                            if (errorCorreo) {

                                console.log(
                                    "âŒ Error verificando correo:",
                                    errorCorreo
                                );

                                return res
                                    .status(500)
                                    .json({
                                        ok: false,
                                        mensaje:
                                            "No se pudo verificar el correo"
                                    });

                            }


                            if (
                                correos.length > 0
                            ) {

                                return res
                                    .status(409)
                                    .json({
                                        ok: false,
                                        mensaje:
                                            "Este correo ya estÃ¡ registrado"
                                    });

                            }


                            // ======================================================
                            // PREPARAR CONTRASEÃ‘A
                            // ======================================================

                            let nuevoHash =
                                usuarioActual.password;


                            if (cambioPassword) {

                                nuevoHash =
                                    await bcrypt.hash(
                                        passwordNuevaLimpio,
                                        10
                                    );

                            }


                            // ======================================================
                            // ACTUALIZAR PERFIL
                            // ======================================================

                            conexion.query(
                                `
                                UPDATE usuarios
                                SET
                                    nombre = ?,
                                    apellido = ?,
                                    telefono = ?,
                                    correo = ?,
                                    provincia = ?,
                                    canton = ?,
                                    distrito = ?,
                                    direccion_exacta = ?,
                                    password = ?,
                                    ultimo_cambio_password =
                                        CASE
                                            WHEN ? = 1
                                            THEN NOW()
                                            ELSE ultimo_cambio_password
                                        END
                                WHERE id_usuario = ?
                                AND tipo_usuario = 'cliente'
                                `,
                                [
                                    nombreLimpio,
                                    apellidoLimpio,
                                    telefonoLimpio,
                                    correoLimpio,
                                    provinciaLimpia,
                                    cantonLimpio,
                                    distritoLimpio,
                                    direccionLimpia || null,
                                    nuevoHash,
                                    cambioPassword ? 1 : 0,
                                    idUsuario
                                ],
                                (
                                    errorActualizar,
                                    resultado
                                ) => {

                                    if (
                                        errorActualizar
                                    ) {

                                        console.log(
                                            "âŒ Error actualizando perfil:",
                                            errorActualizar
                                        );

                                        return res
                                            .status(500)
                                            .json({
                                                ok: false,
                                                mensaje:
                                                    "No se pudo actualizar el perfil"
                                            });

                                    }


                                    if (
                                        resultado
                                            .affectedRows === 0
                                    ) {

                                        return res
                                            .status(404)
                                            .json({
                                                ok: false,
                                                mensaje:
                                                    "Cliente no encontrado"
                                            });

                                    }


                                    // Actualizar nombre guardado
                                    // en la sesiÃ³n actual
                                    req.session.usuario.nombre =
                                        nombreLimpio;


                                    // Si cambiÃ³ correo o contraseÃ±a,
                                    // cerrar la sesiÃ³n por seguridad.
                                    if (
                                        cambioCorreo ||
                                        cambioPassword
                                    ) {

                                        return req.session
                                            .destroy(
                                                (errorSesion) => {

                                                    if (
                                                        errorSesion
                                                    ) {

                                                        console.log(
                                                            "âŒ Error cerrando sesiÃ³n despuÃ©s de actualizar perfil:",
                                                            errorSesion
                                                        );

                                                    }


                                                    res.clearCookie(
                                                        'connect.sid'
                                                    );


                                                    return res.json({
                                                        ok: true,
                                                        mensaje:
                                                            "Perfil actualizado correctamente. Inicie sesiÃ³n nuevamente.",
                                                        cerrarSesion:
                                                            true
                                                    });

                                                }
                                            );

                                    }


                                    return res.json({
                                        ok: true,
                                        mensaje:
                                            "Perfil actualizado correctamente",
                                        cerrarSesion:
                                            false
                                    });

                                }
                            );

                        }
                    );

                }
            );


        } catch (error) {

            console.log(
                "âŒ Error actualizando perfil:",
                error
            );


            return res
                .status(500)
                .json({
                    ok: false,
                    mensaje:
                        "No se pudo actualizar el perfil"
                });

        }

    }
);

// ðŸ”¹ CREAR ARTÃCULO
app.post('/create-article',protegerAdmin, (req, res) => {

    const {
        nombre,
        tasa,
        descripcion
    } = req.body;

    if (!nombre || String(nombre).trim() === '') {
        return res.status(400).json({
            ok: false,
            mensaje: "Nombre de artÃ­culo requerido"
        });
    }

    const nombreLimpio =
        String(nombre).trim();

    const tasaNumero =
        Number(tasa) || 0;

    const descripcionLimpia =
        String(descripcion || '').trim();


    // Primero revisamos si ya existe el mismo nombre.
// Revisamos si ya existe el mismo nombre
// con la misma descripciÃ³n.
conexion.query(`
    SELECT id_articulo
    FROM articulos
    WHERE LOWER(TRIM(nombre)) = LOWER(TRIM(?))
    AND LOWER(TRIM(COALESCE(descripcion, ''))) =
        LOWER(TRIM(?))
    LIMIT 1
`, [
    nombreLimpio,
    descripcionLimpia
], (err, resultados) => {
        if (err) {
            console.log("âŒ Error buscando artÃ­culo:", err);
            return res.status(500).json({
                ok: false
            });
        }

        if (resultados.length > 0) {

            return res.status(409).json({
                ok: false,
                mensaje: "Este artÃ­culo ya existe con la misma descripciÃ³n"
            });

        }

        conexion.query(`
            INSERT INTO articulos
            (
                nombre,
                tasa,
                descripcion
            )
            VALUES (?, ?, ?)
        `, [
            nombreLimpio,
            tasaNumero,
            descripcionLimpia
        ], (err, result) => {

            if (err) {
                console.log("âŒ Error guardando artÃ­culo:", err);
                return res.status(500).json({
                    ok: false
                });
            }

            res.json({
                ok: true,
                id_articulo: result.insertId
            });

        });

    });

});
// ðŸ”¹ ACTUALIZAR ARTÃCULO
app.post('/update-article',protegerAdmin, (req, res) => {

    const {
        id_articulo,
        nombre,
        tasa,
        descripcion
    } = req.body;

    const nombreLimpio =
        String(nombre || '').trim();

    const tasaNumero =
        Number(tasa);

    const descripcionLimpia =
        String(descripcion || '').trim();

    if(
        !id_articulo ||
        !nombreLimpio ||
        !Number.isFinite(tasaNumero) ||
        tasaNumero < 0
    ){
        return res.status(400).json({
            ok:false,
            mensaje:"Datos invÃ¡lidos"
        });
    }

    conexion.query(`
        UPDATE articulos
        SET
            nombre = ?,
            tasa = ?,
            descripcion = ?
        WHERE id_articulo = ?
    `, [
        nombreLimpio,
        tasaNumero,
        descripcionLimpia || null,
        id_articulo
    ], (err, result) => {

        if(err){

            console.log(
                "âŒ Error actualizando artÃ­culo:",
                err
            );

            return res.status(500).json({
                ok:false,
                mensaje:"No se pudo actualizar el artÃ­culo"
            });
        }

        if(result.affectedRows === 0){

            return res.status(404).json({
                ok:false,
                mensaje:"ArtÃ­culo no encontrado"
            });
        }

        res.json({
            ok:true
        });

    });

});

// ðŸ”¹ ELIMINAR ARTÃCULO
app.post(
    '/delete-article',
    protegerAdmin,
    (req, res) => {

        const idArticulo =
            Number(
                req.body.id_articulo
            );

        if(
            !Number.isInteger(idArticulo) ||
            idArticulo <= 0
        ){

            return res.status(400).json({
                ok: false,
                mensaje:
                    "ArtÃ­culo invÃ¡lido"
            });

        }

        conexion.query(`
            DELETE FROM articulos
            WHERE id_articulo = ?
        `, [
            idArticulo
        ], (err, result) => {

            if(err){

                console.log(
                    "âŒ Error eliminando artÃ­culo:",
                    err
                );

                return res.status(500).json({
                    ok: false,
                    mensaje:
                        "No se pudo eliminar el artÃ­culo"
                });

            }

            if(
                result.affectedRows === 0
            ){

                return res.status(404).json({
                    ok: false,
                    mensaje:
                        "ArtÃ­culo no encontrado"
                });

            }

            return res.json({
                ok: true,
                mensaje:
                    "ArtÃ­culo eliminado exitosamente"
            });

        });

    }
);

// ðŸ”¹ EDITAR PEDIDO
app.post(
    '/update-order',
    protegerAdmin,
    (req, res) => {

        const {
            id_pedido,
            id_articulo,
            cantidad
        } = req.body;


        const idPedido =
            Number(id_pedido);

        const idArticulo =
            Number(id_articulo);

        const cantidadNumero =
            Number(cantidad);


        /* =====================================================
           VALIDAR DATOS
        ===================================================== */

        if(
            !Number.isInteger(idPedido) ||
            idPedido <= 0 ||
            !Number.isInteger(idArticulo) ||
            idArticulo <= 0 ||
            !Number.isInteger(cantidadNumero) ||
            cantidadNumero <= 0
        ){

            return res
                .status(400)
                .json({
                    ok: false,
                    mensaje:
                        "Datos invÃ¡lidos"
                });

        }


        /* =====================================================
           BUSCAR ARTÃCULO DEL CATÃLOGO
        ===================================================== */

        conexion.query(
            `
                SELECT
                    id_articulo,
                    nombre,
                    tasa,
                    descripcion
                FROM articulos
                WHERE id_articulo = ?
                LIMIT 1
            `,
            [
                idArticulo
            ],
            (
                err,
                resultados
            ) => {

                if(err){

                    console.log(
                        "âŒ Error buscando artÃ­culo:",
                        err
                    );

                    return res
                        .status(500)
                        .json({
                            ok: false,
                            mensaje:
                                "Error al buscar el artÃ­culo"
                        });

                }


                if(
                    !resultados ||
                    resultados.length === 0
                ){

                    return res
                        .status(404)
                        .json({
                            ok: false,
                            mensaje:
                                "ArtÃ­culo no encontrado"
                        });

                }


                const articulo =
                    resultados[0];


                const precioUnidad =
                    Number(
                        articulo.tasa
                    ) || 0;


                const totalPrecio =
                    cantidadNumero *
                    precioUnidad;


                /* =====================================================
                   ACTUALIZAR SOLO ARTÃCULO Y CANTIDAD

                   IMPORTANTE:
                   NO TOCAR peso_gramos.

                   El peso ahora se maneja aparte
                   como peso general de la factura.
                ===================================================== */

                conexion.query(
                    `
                        UPDATE pedidos
                        SET
                            id_articulo = ?,
                            articulo = ?,
                            descripcion = ?,
                            cantidad = ?,
                            precio_unidad = ?,
                            total_precio = ?
                        WHERE id_pedido = ?
                    `,
                    [
                        articulo.id_articulo,
                        articulo.nombre,
                        articulo.descripcion || null,
                        cantidadNumero,
                        precioUnidad,
                        totalPrecio,
                        idPedido
                    ],
                    (
                        err,
                        resultado
                    ) => {

                        if(err){

                            console.log(
                                "âŒ Error actualizando pedido:",
                                err
                            );

                            return res
                                .status(500)
                                .json({
                                    ok: false,
                                    mensaje:
                                        "Error al actualizar el pedido"
                                });

                        }


                        if(
                            resultado.affectedRows === 0
                        ){

                            return res
                                .status(404)
                                .json({
                                    ok: false,
                                    mensaje:
                                        "Pedido no encontrado"
                                });

                        }


                        return res.json({
                            ok: true,
                            mensaje:
                                "Pedido actualizado correctamente"
                        });

                    }
                );

            }
        );

    }
);
// ðŸ”¹ OBTENER USUARIO
app.get('/user/:id', (req, res) => {

    // ðŸ” Debe existir una sesiÃ³n iniciada
    if (!req.session.usuario) {
        return res.redirect('/login.html');
    }

    const rol = req.session.usuario.tipo_usuario;

    let id;

    // ðŸ” El cliente solo puede consultar sus propios datos
    if (rol === 'cliente') {

        id = req.session.usuario.id_usuario;

    }
    // ðŸ” Admin y superadmin pueden consultar al cliente solicitado
    else if (
        rol === 'admin' ||
        rol === 'superadmin'
    ) {

        id = req.params.id;

    }
    else {

        return res
            .status(403)
            .send('Acceso no autorizado âŒ');

    }

    conexion.query(`
        SELECT
            nombre,
            apellido,
            telefono,
            correo,
            provincia,
            canton,
            distrito,
            direccion_exacta
        FROM usuarios
        WHERE id_usuario = ?
    `, [id], (err, results) => {

        if (err || results.length === 0) {
            return res.json({});
        }

        res.json(results[0]);

    });
});


// ========================================
// ðŸ”¥ GRUPOS DE COMPRA / FACTURAS
// ========================================


/*
    ðŸ”¹ CREAR NUEVA COMPRA

    Cada vez que Ana inicia una compra nueva
    en EEUU o Colombia, se crea un grupo nuevo.

    Ejemplo:
    grupo 1 = EEUU
    grupo 2 = Colombia
    grupo 3 = EEUU
/*
    ðŸ”¹ OBTENER O CREAR FACTURA ACTIVA

    REGLA:

    Un cliente puede tener solamente UNA factura
    activa por paÃ­s.

    Ejemplo:

    Justin + EEUU
    â†’ todos los artÃ­culos nuevos de EEUU
      entran en la misma factura activa.

    Justin + COLOMBIA
    â†’ todos los artÃ­culos nuevos de Colombia
      entran en la misma factura activa.

    Cuando una factura se archiva, deja de
    considerarse activa para ese cliente y paÃ­s.
*/

app.post(
    '/create-purchase-group',
    protegerAdmin,
    (req, res) => {

        const idUsuario =
            Number(
                req.body.id_usuario
            );


        const paisOrigen =
            String(
                req.body.pais_origen || ''
            )
            .trim()
            .toUpperCase();


        const paisesValidos = [
            'EEUU',
            'COLOMBIA'
        ];

        // =============================================
        // FACTURA 1 / 2 / 3 DEL CLIENTE
        // =============================================

        const slotFactura =
            Number(
                req.body.slot_factura || 1
            );


        if(
            !Number.isInteger(slotFactura) ||
            slotFactura < 1 ||
            slotFactura > 3
        ){

            return res.status(400).json({
                ok: false,
                mensaje:
                    'NÃºmero de factura invÃ¡lido'
            });

        }


        /* =============================================
           VALIDAR CLIENTE
        ============================================= */

        if(
            !Number.isInteger(idUsuario) ||
            idUsuario <= 0
        ){

            return res.status(400).json({
                ok: false,
                mensaje:
                    'Cliente invÃ¡lido'
            });

        }


        /* =============================================
           VALIDAR PAÃS
        ============================================= */

        if(
            !paisesValidos.includes(
                paisOrigen
            )
        ){

            return res.status(400).json({
                ok: false,
                mensaje:
                    'PaÃ­s de origen invÃ¡lido'
            });

        }


        /*
            =============================================
            BUSCAR FACTURA ACTIVA DEL CLIENTE + PAÃS

            Una factura se considera disponible si
            todavÃ­a tiene al menos un pedido NO
            archivado de ese cliente y ese paÃ­s.
            =============================================
        */

        conexion.query(`
            SELECT
                p.grupo_compra,
                g.numero_factura

            FROM pedidos p

            INNER JOIN grupos_compra g
                ON g.id_grupo = p.grupo_compra

            WHERE p.id_usuario = ?
            AND p.pais_origen = ?
            AND g.slot_factura = ?
            AND p.archivado = 0
            AND p.grupo_compra IS NOT NULL
            AND g.activo = 1

            ORDER BY
                p.id_pedido DESC

            LIMIT 1
        `, [
            idUsuario,
            paisOrigen,
            slotFactura
        ], (errorBuscar, resultados) => {


            if(errorBuscar){

                console.log(
                    'âŒ ERROR BUSCANDO FACTURA ACTIVA:',
                    errorBuscar
                );


                return res.status(500).json({
                    ok: false,
                    mensaje:
                        'No se pudo buscar la factura activa'
                });

            }


            /*
                =========================================
                YA EXISTE FACTURA ACTIVA

                NO creamos otra.
                Devolvemos el grupo existente.
                =========================================
            */

            if(
                resultados &&
                resultados.length > 0
            ){

                const grupoExistente =
                    Number(
                        resultados[0]
                            .grupo_compra
                    );


                return res.json({
                    ok: true,

                    grupo_compra:
                        grupoExistente,
                    
                    numero_factura:
                      resultados[0].numero_factura,


                    pais_origen:
                        paisOrigen,

                    existente:
                        true
                });

            }


            /*
                =========================================
                NO EXISTE FACTURA ACTIVA

                Ahora sÃ­ creamos un grupo nuevo.
                =========================================
            */
conexion.beginTransaction((errorTransaccion) => {

    if (errorTransaccion) {

        console.log(
            'âŒ ERROR INICIANDO TRANSACCIÃ“N:',
            errorTransaccion
        );

        return res.status(500).json({
            ok: false,
            mensaje: 'No se pudo crear la factura'
        });
    }


    conexion.query(`
        SELECT ultimo_numero
        FROM contador_facturas
        WHERE id = 1
        FOR UPDATE
    `, (errorContador, contador) => {

        if (
            errorContador ||
            !contador ||
            contador.length === 0
        ) {

            return conexion.rollback(() => {

                console.log(
                    'âŒ ERROR LEYENDO CONTADOR DE FACTURAS:',
                    errorContador
                );

                return res.status(500).json({
                    ok: false,
                    mensaje:
                        'No se pudo obtener el nÃºmero de factura'
                });
            });
        }


        const nuevoNumero =
            Number(contador[0].ultimo_numero) + 1;


        conexion.query(`
            UPDATE contador_facturas
            SET ultimo_numero = ?
            WHERE id = 1
        `, [
            nuevoNumero
        ], (errorActualizar) => {

            if (errorActualizar) {

                return conexion.rollback(() => {

                    console.log(
                        'âŒ ERROR ACTUALIZANDO CONTADOR:',
                        errorActualizar
                    );

                    return res.status(500).json({
                        ok: false,
                        mensaje:
                            'No se pudo generar el nÃºmero de factura'
                    });
                });
            }


            conexion.query(`
                INSERT INTO grupos_compra
                (
                    pais_origen,
                    activo,
                    slot_factura,
                    numero_factura
                )
                VALUES (?, 1, ?, ?)
            `, [
                paisOrigen,
                slotFactura,
                nuevoNumero
            ], (errorCrear, resultado) => {

                if (errorCrear) {

                    return conexion.rollback(() => {

                        console.log(
                            'âŒ ERROR CREANDO GRUPO DE COMPRA:',
                            errorCrear
                        );

                        return res.status(500).json({
                            ok: false,
                            mensaje:
                                'No se pudo crear la factura'
                        });
                    });
                }


                conexion.commit((errorCommit) => {

                    if (errorCommit) {

                        return conexion.rollback(() => {

                            console.log(
                                'âŒ ERROR CONFIRMANDO FACTURA:',
                                errorCommit
                            );

                            return res.status(500).json({
                                ok: false,
                                mensaje:
                                    'No se pudo crear la factura'
                            });
                        });
                    }


                    return res.json({
                        ok: true,

                        grupo_compra:
                            resultado.insertId,

                        numero_factura:
                            nuevoNumero,

                        pais_origen:
                            paisOrigen,

                        existente:
                            false
                    });

                });

            });

        });

    });

});

/*
    Cierra conexion.query() de
    BUSCAR FACTURA ACTIVA
*/
});

/*
    Cierra app.post('/create-purchase-group')
*/
});

// ======================================================
// ðŸ”¹ CREAR PEDIDO
// ======================================================

app.post('/create-order', protegerAdmin, (req, res) => {

    const {
        id_usuario,
        id_articulo,
        articulo,
        descripcion,
        nota,
        cantidad,
        precio_unidad,
        estado,
        pais_origen,
        grupo_compra
    } = req.body;


    // ======================================================
    // ðŸ” NORMALIZAR DATOS
    // ======================================================

    const idUsuario =
        Number(id_usuario);

    const idArticulo =
        id_articulo
            ? Number(id_articulo)
            : null;

    const cantidadNumero =
        Number(cantidad);

    const precioUnidad =
        Number(precio_unidad);

    const grupoCompra =
        Number(grupo_compra);

    const articuloLimpio =
        String(articulo || '').trim();

    const descripcionLimpia =
        String(descripcion || '').trim();
    const notaLimpia =
     String(nota || '').trim();


    // ======================================================
    // ðŸ” VALIDAR CLIENTE
    // ======================================================

    if(
        !Number.isInteger(idUsuario) ||
        idUsuario <= 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: 'Cliente invÃ¡lido'
        });

    }


    // ======================================================
    // ðŸ” VALIDAR ARTÃCULO
    // ======================================================

    if(
        !articuloLimpio
    ){

        return res.status(400).json({
            ok: false,
            mensaje: 'ArtÃ­culo invÃ¡lido'
        });

    }


    // ======================================================
    // ðŸ” VALIDAR CANTIDAD
    // ======================================================

    if(
        !Number.isFinite(cantidadNumero) ||
        cantidadNumero <= 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: 'Cantidad invÃ¡lida'
        });

    }


    // ======================================================
    // ðŸ” VALIDAR PRECIO
    // ======================================================

    if(
        !Number.isFinite(precioUnidad) ||
        precioUnidad < 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: 'Precio invÃ¡lido'
        });

    }


    // ======================================================
    // ðŸ” VALIDAR GRUPO / FACTURA
    // ======================================================

    if(
        !Number.isInteger(grupoCompra) ||
        grupoCompra <= 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: 'Factura invÃ¡lida'
        });

    }


    // ======================================================
    // ðŸ” NORMALIZAR PAÃS
    // ======================================================

    let paisOrigen =
        String(
            pais_origen || ''
        )
        .trim()
        .toUpperCase();


    /*
        TambiÃ©n aceptamos el valor antiguo
        que utiliza el botÃ³n del dashboard.
    */

    if(
        paisOrigen === 'EN_EEUU'
    ){

        paisOrigen =
            'EEUU';

    }


    const paisesValidos = [
        'EEUU',
        'COLOMBIA'
    ];


    if(
        !paisesValidos.includes(
            paisOrigen
        )
    ){

        return res.status(400).json({
            ok: false,
            mensaje:
                'PaÃ­s de origen invÃ¡lido'
        });

    }


    // ======================================================
    // ðŸ”¹ ESTADO INICIAL SEGÃšN PAÃS
    // ======================================================

    const estadoInicial =
        paisOrigen === 'COLOMBIA'
            ? 'COLOMBIA'
            : 'En_EEUU';


    // ======================================================
    // ðŸ” COMPROBAR QUE EL CLIENTE EXISTE
    // ======================================================

    conexion.query(`
        SELECT
            id_usuario
        FROM usuarios
        WHERE id_usuario = ?
        AND tipo_usuario = 'cliente'
        LIMIT 1
    `, [
        idUsuario
    ], (errorCliente, clientes) => {


        if(errorCliente){

            console.log(
                'âŒ Error verificando cliente:',
                errorCliente
            );

            return res.status(500).json({
                ok: false,
                mensaje:
                    'No se pudo verificar el cliente'
            });

        }


        if(
            !clientes ||
            clientes.length === 0
        ){

            return res.status(404).json({
                ok: false,
                mensaje:
                    'Cliente no encontrado'
            });

        }


        // ==================================================
        // ðŸ” COMPROBAR GRUPO / FACTURA
        // ==================================================

        conexion.query(`
            SELECT
                id_grupo,
                pais_origen,
                activo
            FROM grupos_compra
            WHERE id_grupo = ?
            LIMIT 1
        `, [
            grupoCompra
        ], (errorGrupo, grupos) => {


            if(errorGrupo){

                console.log(
                    'âŒ Error verificando factura:',
                    errorGrupo
                );

                return res.status(500).json({
                    ok: false,
                    mensaje:
                        'No se pudo verificar la factura'
                });

            }


            if(
                !grupos ||
                grupos.length === 0
            ){

                return res.status(404).json({
                    ok: false,
                    mensaje:
                        'Factura no encontrada'
                });

            }


            const grupo =
                grupos[0];


            // ==================================================
            // ðŸ” FACTURA DEBE ESTAR ACTIVA
            // ==================================================

            if(
                Number(grupo.activo) !== 1
            ){

                return res.status(400).json({
                    ok: false,
                    mensaje:
                        'La factura ya no estÃ¡ activa'
                });

            }


            // ==================================================
            // ðŸ” PAÃS DE FACTURA DEBE COINCIDIR
            // ==================================================

            if(
                String(
                    grupo.pais_origen
                ).toUpperCase() !==
                paisOrigen
            ){

                return res.status(400).json({
                    ok: false,
                    mensaje:
                        'El paÃ­s de la factura no coincide con el pedido'
                });

            }


            /*
                ==================================================
                ðŸ” EVITAR MEZCLAR CLIENTES EN UNA FACTURA

                Si el grupo ya tiene pedidos activos,
                todos deben pertenecer al mismo cliente.
                ==================================================
            */

            conexion.query(`
                SELECT
                    id_usuario
                FROM pedidos
                WHERE grupo_compra = ?
                AND archivado = 0
                LIMIT 1
            `, [
                grupoCompra
            ], (errorPedidoGrupo, pedidosGrupo) => {


                if(errorPedidoGrupo){

                    console.log(
                        'âŒ Error verificando pedidos de la factura:',
                        errorPedidoGrupo
                    );

                    return res.status(500).json({
                        ok: false,
                        mensaje:
                            'No se pudo verificar la factura'
                    });

                }


                if(
                    pedidosGrupo &&
                    pedidosGrupo.length > 0 &&
                    Number(
                        pedidosGrupo[0].id_usuario
                    ) !== idUsuario
                ){

                    return res.status(400).json({
                        ok: false,
                        mensaje:
                            'Esta factura pertenece a otro cliente'
                    });

                }


                // ==============================================
                // ðŸ”¹ CALCULAR TOTAL DEL PRODUCTO
                // ==============================================

                const totalPrecio =
                    cantidadNumero *
                    precioUnidad;


                // ==============================================
                // ðŸ”¹ GUARDAR PEDIDO
                // ==============================================

                conexion.query(`
                    INSERT INTO pedidos
                    (
                        id_usuario,
                        id_articulo,
                        articulo,
                        descripcion,
                        nota,
                        cantidad,
                        precio_unidad,
                        peso_gramos,
                        total_precio,
                        estado,
                        pais_origen,
                        grupo_compra,
                        archivado
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, 0)
                `, [
                    idUsuario,
                    idArticulo,
                    articuloLimpio,
                    descripcionLimpia || null,
                    notaLimpia || null,
                    cantidadNumero,
                    precioUnidad,
                    totalPrecio,
                    estadoInicial,
                    paisOrigen,
                    grupoCompra
                ], (errorInsertar, resultado) => {


                    if(errorInsertar){

                        console.log(
                            'âŒ Error creando pedido:',
                            errorInsertar
                        );

                        return res.status(500).json({
                            ok: false,
                            mensaje:
                                'No se pudo crear el pedido'
                        });

                    }


                    return res.json({
                        ok: true,
                        mensaje:
                            'Pedido creado correctamente',
                        id_pedido:
                            resultado.insertId,
                        grupo_compra:
                            grupoCompra,
                        pais_origen:
                            paisOrigen
                    });

                });

            });

        });

    });

});

// ======================================================
// ðŸ”¹ ACTUALIZAR ARTÃCULO DE UN PEDIDO / FACTURA
// ======================================================

app.post('/update-order-detail', protegerAdmin, (req, res) => {

    console.log(
    'ðŸŸ£ UPDATE ORDER RECIBIDO:',
    req.body
   );


    const {
        id_pedido,
        articulo,
        descripcion,
        nota,
        cantidad,
        precio_unidad
    } = req.body;


    const idPedido =
        Number(id_pedido);

    const cantidadNumero =
        Number(cantidad);

    const precioUnidad =
        Number(precio_unidad);


    if(
        !Number.isInteger(idPedido) ||
        idPedido <= 0
    ){
        return res.status(400).json({
            ok: false,
            mensaje: 'Pedido invÃ¡lido'
        });
    }


    if(
        !Number.isFinite(cantidadNumero) ||
        cantidadNumero <= 0
    ){
        return res.status(400).json({
            ok: false,
            mensaje: 'Cantidad invÃ¡lida'
        });
    }


    if(
        !Number.isFinite(precioUnidad) ||
        precioUnidad < 0
    ){
        return res.status(400).json({
            ok: false,
            mensaje: 'Precio invÃ¡lido'
        });
    }


    const articuloLimpio =
        String(articulo || '').trim();

    const descripcionLimpia =
        String(descripcion || '').trim();

    const notaLimpia =
        String(nota || '').trim();


    if(!articuloLimpio){
        return res.status(400).json({
            ok: false,
            mensaje: 'El artÃ­culo es obligatorio'
        });
    }


    const totalPrecio =
        cantidadNumero * precioUnidad;


    conexion.query(`
        UPDATE pedidos
        SET
            articulo = ?,
            descripcion = ?,
            nota = ?,
            cantidad = ?,
            precio_unidad = ?,
            total_precio = ?
        WHERE id_pedido = ?
    `, [
        articuloLimpio,
        descripcionLimpia || null,
        notaLimpia || null,
        cantidadNumero,
        precioUnidad,
        totalPrecio,
        idPedido
    ], (error, resultado) => {

        if(error){

            console.log(
                'âŒ Error actualizando pedido:',
                error
            );

            return res.status(500).json({
                ok: false,
                mensaje:
                    'No se pudo actualizar el artÃ­culo'
            });
        }


        if(resultado.affectedRows === 0){

            return res.status(404).json({
                ok: false,
                mensaje:
                    'No se encontrÃ³ el artÃ­culo del pedido'
            });
        }


        return res.json({
            ok: true,
            mensaje:
                'ArtÃ­culo actualizado correctamente'
        });

    });

});


// ðŸ”¹ CALCULAR ENVÃO
app.post('/calcular-envio', (req, res) => {
    const { peso_gramos } = req.body;
    const peso = Number(peso_gramos) || 0;
    const envio = (peso / 1000) * 6000;

    res.json({ ok: true, envio });
});

// ======================================================
// ðŸ”¹ CARGAR PEDIDO ACTIVO DE UN CLIENTE + PAÃS
// ======================================================

app.get(
    '/active-order/:id_usuario',
    protegerAdmin,
    (req, res) => {

        const idUsuario =
            Number(
                req.params.id_usuario
            );


        const paisOrigen =
            String(
                req.query.pais_origen || ''
            )
            .trim()
            .toUpperCase();


        // ======================================================
        // FACTURA 1 / 2 / 3
        // ======================================================

        const slotFactura =
            Number(
                req.query.slot_factura || 1
            );


        if(
            !Number.isInteger(slotFactura) ||
            slotFactura < 1 ||
            slotFactura > 3
        ){

            return res.status(400).json({
                ok:false,
                mensaje:'Numero de factura invalido'
            });

        }


        // ======================================================
        // ðŸ” VALIDAR CLIENTE
        // ======================================================

        if(
            !Number.isInteger(idUsuario) ||
            idUsuario <= 0
        ){

            return res.status(400).json({
                ok:false,
                mensaje:'Cliente invÃ¡lido'
            });

        }


        // ======================================================
        // ðŸ” VALIDAR PAÃS
        // ======================================================

        const paisesValidos = [
            'EEUU',
            'COLOMBIA'
        ];


        if(
            !paisesValidos.includes(
                paisOrigen
            )
        ){

            return res.status(400).json({
                ok:false,
                mensaje:'PaÃ­s de origen invÃ¡lido'
            });

        }


        // ======================================================
        // ðŸ”¥ BUSCAR FACTURA ACTIVA DEL CLIENTE + PAÃS
        // ======================================================

        conexion.query(`
            SELECT
                p.grupo_compra,
                p.pais_origen

            FROM pedidos p

            INNER JOIN grupos_compra g
                ON g.id_grupo = p.grupo_compra

            WHERE p.id_usuario = ?
            AND p.pais_origen = ?
            AND g.slot_factura = ?
            AND p.archivado = 0
            AND p.grupo_compra IS NOT NULL
            AND g.activo = 1

            ORDER BY p.id_pedido DESC

            LIMIT 1
        `, [
            idUsuario,
            paisOrigen,
            slotFactura

        ], (errorGrupo, grupos) => {


            if(errorGrupo){

                console.log(
                    'âŒ Error buscando pedido activo:',
                    errorGrupo
                );

                return res.status(500).json({
                    ok:false,
                    mensaje:
                        'No se pudo cargar el pedido activo'
                });

            }


            if(
                !grupos ||
                grupos.length === 0
            ){

                return res.json({
                    ok:true,
                    existe:false,
                    pais_origen:
                        paisOrigen,
                    pedidos:[]
                });

            }


            const grupoCompra =
                Number(
                    grupos[0].grupo_compra
                );


            // ======================================================
            // ðŸ”¥ CARGAR SOLO LOS ARTÃCULOS DE ESA FACTURA
            // ======================================================

            conexion.query(`
                SELECT
                    id_pedido,
                    id_articulo,
                    articulo,
                    descripcion,
                    nota,
                    cantidad,
                    precio_unidad,
                    total_precio,
                    estado,
                    pais_origen,
                    grupo_compra

                FROM pedidos

                WHERE id_usuario = ?
                AND grupo_compra = ?
                AND pais_origen = ?
                AND archivado = 0

                ORDER BY id_pedido ASC
            `, [
                idUsuario,
                grupoCompra,
                paisOrigen

            ], (errorPedidos, pedidos) => {


                if(errorPedidos){

                    console.log(
                        'âŒ Error cargando artÃ­culos del pedido:',
                        errorPedidos
                    );

                    return res.status(500).json({
                        ok:false,
                        mensaje:
                            'No se pudieron cargar los artÃ­culos'
                    });

                }

const idsPedidos =
    pedidos.map(
        pedido =>
            pedido.id_pedido
    );


if(idsPedidos.length === 0){

    return res.json({

        ok:true,

        existe:true,

        grupo_compra:
            grupoCompra,

        pais_origen:
            paisOrigen,

        total_abonado:
            0,

        pedidos:
            pedidos

    });

}


conexion.query(
    `
        SELECT
            IFNULL(
                SUM(monto_abono),
                0
            ) AS total_abonado

        FROM abonos

        WHERE id_pedido IN (?)
    `,
    [
        idsPedidos
    ],
    (
        errorAbonos,
        resultadosAbonos
    ) => {

        if(errorAbonos){

            console.log(
                'âŒ Error cargando abonos de la factura:',
                errorAbonos
            );

            return res.status(500).json({
                ok:false,
                mensaje:
                    'No se pudieron cargar los abonos de la factura'
            });

        }


        const totalAbonado =
            Number(
                resultadosAbonos[0]
                    .total_abonado
            ) || 0;


        return res.json({

            ok:true,

            existe:true,

            grupo_compra:
                grupoCompra,

            pais_origen:
                paisOrigen,

            total_abonado:
                totalAbonado,

            pedidos:
                pedidos

        });

    }
);

            });

        });

    }
);
// ======================================================
// ðŸ”¹ VER PEDIDOS ACTIVOS ADMIN
// ======================================================

app.get('/orders', protegerAdmin, (req, res) => {

    conexion.query(`
        SELECT
            p.*,
            u.nombre,
            u.apellido,
            g.numero_factura,
            g.tarifa_envio_personalizada,
            IFNULL(SUM(a.monto_abono), 0) AS total_abonado,
            MAX(a.metodo_pago) AS metodo_pago,
            MAX(a.fecha_abono) AS fecha_abono,
            (p.total_precio - IFNULL(SUM(a.monto_abono), 0)) AS deuda

        FROM pedidos p

        JOIN usuarios u
            ON p.id_usuario = u.id_usuario
        JOIN grupos_compra g
         ON p.grupo_compra = g.id_grupo

        LEFT JOIN abonos a
            ON p.id_pedido = a.id_pedido

        WHERE p.archivado = 0

        GROUP BY p.id_pedido

        ORDER BY
            u.nombre ASC,
            u.apellido ASC,
            p.grupo_compra ASC,
            p.id_pedido ASC

    `, (err, results) => {

        if (err) {

            console.log(
                "âŒ Error cargando pedidos activos:",
                err
            );

            return res.json([]);
        }

        res.json(results);

    });

});

// ======================================================
// ðŸ”¹ VER PEDIDOS ARCHIVADOS
// ======================================================

app.get('/archived-orders', protegerAdmin, (req, res) => {

    conexion.query(`
        SELECT
            p.*,
            u.nombre,
            u.apellido,
            g.numero_factura,
            IFNULL(SUM(a.monto_abono), 0) AS total_abonado,
            MAX(a.metodo_pago) AS metodo_pago,
            MAX(a.fecha_abono) AS fecha_abono,
            (p.total_precio - IFNULL(SUM(a.monto_abono), 0)) AS deuda

        FROM pedidos p

        JOIN usuarios u
            ON p.id_usuario = u.id_usuario

        JOIN grupos_compra g
         ON p.grupo_compra = g.id_grupo

        LEFT JOIN abonos a
            ON p.id_pedido = a.id_pedido

        WHERE p.archivado = 1

        GROUP BY p.id_pedido

        ORDER BY p.fecha_archivado DESC

    `, (err, results) => {

        if (err) {

            console.log(
                "âŒ Error cargando pedidos archivados:",
                err
            );

            return res.status(500).json([]);
        }

        res.json(results);

    });

});

// ======================================================
// ðŸ”¹ ARCHIVAR PEDIDOS ACTIVOS DE UNA FACTURA DEL CLIENTE
// ======================================================

app.post('/archive-client-orders', protegerAdmin, (req, res) => {

    const idUsuario =
        Number(req.body.id_usuario);

    const grupoCompra =
        Number(req.body.grupo_compra);


    // ======================================================
    // ðŸ” VALIDAR CLIENTE
    // ======================================================

    if(
        !Number.isInteger(idUsuario) ||
        idUsuario <= 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: "Cliente invÃ¡lido"
        });

    }


    // ======================================================
    // ðŸ” VALIDAR GRUPO / FACTURA
    // ======================================================

    if(
        !Number.isInteger(grupoCompra) ||
        grupoCompra <= 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: "Factura invÃ¡lida"
        });

    }


    // ======================================================
    // ðŸ”¹ ARCHIVAR SOLO ESA FACTURA DEL CLIENTE
    // ======================================================

    conexion.query(`
        UPDATE pedidos

        SET
            archivado = 1,
            fecha_archivado = NOW()

        WHERE id_usuario = ?
        AND grupo_compra = ?
        AND archivado = 0

    `, [
        idUsuario,
        grupoCompra
    ], (err, resultado) => {

        if(err){

            console.log(
                "âŒ Error archivando factura:",
                err
            );

            return res.status(500).json({
                ok: false,
                mensaje:
                    "No se pudo archivar la factura"
            });

        }


        if(
            resultado.affectedRows === 0
        ){

            return res.status(404).json({
                ok: false,
                mensaje:
                    "No hay pedidos activos en esta factura para archivar"
            });

        }


        return res.json({
            ok: true,
            mensaje:
                "Factura archivada correctamente",
            pedidos_archivados:
                resultado.affectedRows
        });

    });

});

// ======================================================
// ðŸ”¹ DESARCHIVAR UNA FACTURA DEL CLIENTE
// ======================================================

app.post('/unarchive-client-orders', protegerAdmin, (req, res) => {

    const idUsuario =
        Number(req.body.id_usuario);

    const grupoCompra =
        Number(req.body.grupo_compra);


    // ======================================================
    // ðŸ” VALIDAR CLIENTE
    // ======================================================

    if(
        !Number.isInteger(idUsuario) ||
        idUsuario <= 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: "Cliente invÃ¡lido"
        });

    }


    // ======================================================
    // ðŸ” VALIDAR GRUPO / FACTURA
    // ======================================================

    if(
        !Number.isInteger(grupoCompra) ||
        grupoCompra <= 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: "Factura invÃ¡lida"
        });

    }


    // ======================================================
    // ðŸ”¹ DESARCHIVAR SOLO ESA FACTURA DEL CLIENTE
    // ======================================================

    conexion.query(`

        UPDATE pedidos

        SET
            archivado = 0,
            fecha_archivado = NULL

        WHERE id_usuario = ?
        AND grupo_compra = ?
        AND archivado = 1

    `, [
        idUsuario,
        grupoCompra
    ], (err, resultado) => {

        if(err){

            console.log(
                "âŒ Error desarchivando factura:",
                err
            );

            return res.status(500).json({
                ok: false,
                mensaje:
                    "No se pudo desarchivar la factura"
            });

        }


        if(
            resultado.affectedRows === 0
        ){

            return res.status(404).json({
                ok: false,
                mensaje:
                    "No se encontrÃ³ la factura archivada"
            });

        }


        return res.json({
            ok: true,
            mensaje:
                "Factura desarchivada correctamente",
            pedidos_desarchivados:
                resultado.affectedRows
        });

    });

});
// ======================================================
// ðŸ”¹ CLIENTE VE SUS PEDIDOS ACTIVOS
// ======================================================

app.get('/client-orders/:id', protegerCliente, (req, res) => {

    // Por seguridad usamos el usuario de la sesiÃ³n
    const id = req.session.usuario.id_usuario;

    conexion.query(`
        SELECT
            p.*,
            g.slot_factura,
            g.numero_factura,
            g.tarifa_envio_personalizada,

            (
                SELECT IFNULL(
                    SUM(a.monto_abono),
                    0
                )
                FROM abonos a
                INNER JOIN pedidos p2
                    ON p2.id_pedido = a.id_pedido
                WHERE
                    p2.id_usuario = p.id_usuario

                    AND (
                        (
                            p.grupo_compra IS NOT NULL
                            AND p2.grupo_compra = p.grupo_compra
                        )

                        OR

                        (
                            p.grupo_compra IS NULL
                            AND p2.id_pedido = p.id_pedido
                        )
                    )
            ) AS total_abonado

        FROM pedidos p

        LEFT JOIN grupos_compra g
            ON g.id_grupo = p.grupo_compra

        WHERE
            p.id_usuario = ?
            AND p.archivado = 0

        ORDER BY
            p.grupo_compra,
            p.id_pedido

    `, [id], (err, results) => {

        if (err) {

            console.log(
                "âŒ Error cargando pedidos del cliente:",
                err
            );

            return res.status(500).json([]);

        }

        res.json(results);

    });

});
// ======================================================
// ðŸ”¹ CLIENTE VE SUS PEDIDOS ARCHIVADOS
// ======================================================

app.get('/client-archived-orders/:id', protegerCliente, (req, res) => {

    // Igual que arriba: el cliente solamente puede
    // consultar los pedidos de su propia sesiÃ³n.
    const id =
        req.session.usuario.id_usuario;


    conexion.query(`
        SELECT
            p.*,
            g.numero_factura,
            IFNULL(
                SUM(a.monto_abono),
                0
            ) AS total_abonado
        FROM pedidos p
        LEFT JOIN grupos_compra g
            ON g.id_grupo = p.grupo_compra
        LEFT JOIN abonos a
            ON p.id_pedido = a.id_pedido
        WHERE
            p.id_usuario = ?
            AND p.archivado = 1
        GROUP BY p.id_pedido
        ORDER BY
            p.fecha_archivado DESC,
            p.id_pedido DESC
    `, [id], (err, results) => {

        if (err) {

            console.log(
                "âŒ Error cargando archivos del cliente:",
                err
            );

            return res.status(500).json([]);

        }


        res.json(results);

    });

});
// ======================================================
// ðŸ”¹ ABONOS
// ======================================================


// ======================================================
// ðŸ”¹ OBTENER ABONOS DE UN PEDIDO
// ======================================================

app.get(
    '/payments/:id_pedido',
    protegerAdmin,
    (req, res) => {

        const idPedido =
            Number(req.params.id_pedido);

        if (
            !Number.isInteger(idPedido) ||
            idPedido <= 0
        ) {

            return res.status(400).json({
                ok: false,
                mensaje: "Pedido invÃ¡lido"
            });

        }

        conexion.query(`
            SELECT
                id_abono,
                id_pedido,
                monto_abono,
                fecha_abono,
                metodo_pago
            FROM abonos
            WHERE id_pedido = ?
            ORDER BY
                fecha_abono DESC,
                id_abono DESC
        `, [
            idPedido
        ], (err, resultados) => {

            if (err) {

                console.log(
                    "âŒ Error cargando abonos:",
                    err
                );

                return res.status(500).json({
                    ok: false,
                    mensaje:
                        "No se pudieron cargar los abonos"
                });

            }

            return res.json({
                ok: true,
                abonos: resultados
            });

        });

    }
);
// ======================================================
// ðŸ”¹ EDITAR UN ABONO
// ======================================================

app.post(
    '/update-payment',
    protegerAdmin,
    (req, res) => {

        const idAbono =
            Number(req.body.id_abono);

        const nuevoMonto = Number(req.body.monto_abono);
        const metodoPago = req.body.metodo_pago == null ? null : String(req.body.metodo_pago).trim();


        // ======================================================
        // VALIDAR DATOS
        // ======================================================

        if (
            !Number.isInteger(idAbono) ||
            idAbono <= 0 ||
            !Number.isFinite(nuevoMonto) ||
            nuevoMonto <= 0
        ) {

            return res.status(400).json({
                ok: false,
                mensaje: "Datos de abono invÃ¡lidos"
            });

        }


        // ======================================================
        // INICIAR TRANSACCIÃ“N
        // ======================================================

        conexion.beginTransaction(
            (errorTransaccion) => {

                if (errorTransaccion) {

                    console.log(
                        "âŒ Error iniciando ediciÃ³n de abono:",
                        errorTransaccion
                    );

                    return res.status(500).json({
                        ok: false,
                        mensaje:
                            "No se pudo iniciar la ediciÃ³n del abono"
                    });

                }


                // ======================================================
                // BUSCAR EL ABONO Y SU PEDIDO
                // ======================================================

                conexion.query(
                    `
                        SELECT
                            a.id_abono,
                            a.id_pedido,
                            a.monto_abono,
                            p.id_usuario,
                            p.grupo_compra,
                            p.archivado

                        FROM abonos a

                        INNER JOIN pedidos p
                            ON p.id_pedido = a.id_pedido

                        WHERE a.id_abono = ?

                        LIMIT 1

                        FOR UPDATE
                    `,
                    [
                        idAbono
                    ],
                    (
                        errorAbono,
                        abonos
                    ) => {

                        if (errorAbono) {

                            return conexion.rollback(
                                () => {

                                    console.log(
                                        "âŒ Error buscando abono:",
                                        errorAbono
                                    );

                                    return res.status(500).json({
                                        ok: false,
                                        mensaje:
                                            "No se pudo verificar el abono"
                                    });

                                }
                            );

                        }


                        if (
                            !abonos ||
                            abonos.length === 0
                        ) {

                            return conexion.rollback(
                                () => {

                                    return res.status(404).json({
                                        ok: false,
                                        mensaje:
                                            "Abono no encontrado"
                                    });

                                }
                            );

                        }


                        const abonoActual =
                            abonos[0];

                        const idUsuario =
                            Number(
                                abonoActual.id_usuario
                            );

                        const grupoCompra =
                            Number(
                                abonoActual.grupo_compra
                            );


                        if (
                            Number(
                                abonoActual.archivado
                            ) === 1
                        ) {

                            return conexion.rollback(
                                () => {

                                    return res.status(400).json({
                                        ok: false,
                                        mensaje:
                                            "No se puede editar un abono de una factura archivada"
                                    });

                                }
                            );

                        }


                        if (
                            !Number.isInteger(grupoCompra) ||
                            grupoCompra <= 0
                        ) {

                            return conexion.rollback(
                                () => {

                                    return res.status(400).json({
                                        ok: false,
                                        mensaje:
                                            "La factura no tiene un grupo vÃ¡lido"
                                    });

                                }
                            );

                        }


                        // ======================================================
                        // BUSCAR TODOS LOS PEDIDOS DE LA FACTURA
                        // ======================================================

                        conexion.query(
                            `
                                SELECT
    p.id_pedido,
    p.peso_gramos,
    p.total_precio,
    g.tarifa_envio_personalizada

FROM pedidos p

INNER JOIN grupos_compra g
    ON g.id_grupo = p.grupo_compra

WHERE p.id_usuario = ?
AND p.grupo_compra = ?
AND p.archivado = 0

FOR UPDATE
                            `,
                            [
                                idUsuario,
                                grupoCompra
                            ],
                            (
                                errorFactura,
                                pedidosFactura
                            ) => {

                                if (errorFactura) {

                                    return conexion.rollback(
                                        () => {

                                            console.log(
                                                "âŒ Error buscando factura:",
                                                errorFactura
                                            );

                                            return res.status(500).json({
                                                ok: false,
                                                mensaje:
                                                    "No se pudo verificar la factura"
                                            });

                                        }
                                    );

                                }


                                if (
                                    !pedidosFactura ||
                                    pedidosFactura.length === 0
                                ) {

                                    return conexion.rollback(
                                        () => {

                                            return res.status(404).json({
                                                ok: false,
                                                mensaje:
                                                    "Factura no encontrada"
                                            });

                                        }
                                    );

                                }


                                const idsPedidos =
                                    pedidosFactura.map(
                                        pedido =>
                                            pedido.id_pedido
                                    );


                                // ======================================================
                                // CALCULAR TOTAL DE LA FACTURA
                                // ======================================================

                                const pesoGeneral =
                                    pedidosFactura.reduce(
                                        (
                                            acumulado,
                                            pedido
                                        ) => {

                                            return acumulado +
                                                (
                                                    Number(
                                                        pedido.peso_gramos
                                                    ) || 0
                                                );

                                        },
                                        0
                                    );


                                const tarifaPersonalizada =
    pedidosFactura[0].tarifa_envio_personalizada;

const envioGeneral =
    tarifaPersonalizada !== null &&
    tarifaPersonalizada !== undefined &&
    tarifaPersonalizada !== ""
        ? Number(tarifaPersonalizada)
        : (pesoGeneral / 1000) * 6000;


                                const subtotalProductos =
                                    pedidosFactura.reduce(
                                        (
                                            acumulado,
                                            pedido
                                        ) => {

                                            return acumulado +
                                                (
                                                    Number(
                                                        pedido.total_precio
                                                    ) || 0
                                                );

                                        },
                                        0
                                    );


                                const totalFactura =
                                    subtotalProductos +
                                    envioGeneral;


                                // ======================================================
                                // SUMAR LOS OTROS ABONOS
                                //
                                // IMPORTANTE:
                                // No contamos el abono que estamos editando.
                                // ======================================================

                                conexion.query(
                                    `
                                        SELECT
                                            IFNULL(
                                                SUM(monto_abono),
                                                0
                                            ) AS otros_abonos

                                        FROM abonos

                                        WHERE id_pedido IN (?)
                                        AND id_abono <> ?
                                    `,
                                    [
                                        idsPedidos,
                                        idAbono
                                    ],
                                    (
                                        errorOtrosAbonos,
                                        resultados
                                    ) => {

                                        if (errorOtrosAbonos) {

                                            return conexion.rollback(
                                                () => {

                                                    console.log(
                                                        "âŒ Error verificando otros abonos:",
                                                        errorOtrosAbonos
                                                    );

                                                    return res.status(500).json({
                                                        ok: false,
                                                        mensaje:
                                                            "No se pudo verificar el saldo de la factura"
                                                    });

                                                }
                                            );

                                        }


                                        const otrosAbonos =
                                            Number(
                                                resultados[0]
                                                    .otros_abonos
                                            ) || 0;


                                        const maximoPermitido =
                                            totalFactura -
                                            otrosAbonos;


                                        // ======================================================
                                        // NO PERMITIR QUE LA EDICIÃ“N
                                        // SUPERE EL TOTAL DE LA FACTURA
                                        // ======================================================

                                        if (
                                            nuevoMonto >
                                            maximoPermitido
                                        ) {

                                            return conexion.rollback(
                                                () => {

                                                    return res.status(400).json({
                                                        ok: false,
                                                        mensaje:
                                                            `El monto mÃ¡ximo permitido para este abono es â‚¡${maximoPermitido.toLocaleString('es-CR').replace(/[\u00A0\u202F ]/g, ".")}.`
                                                    });

                                                }
                                            );

                                        }


                                        // ======================================================
                                        // ACTUALIZAR ABONO
                                        // ======================================================

                                        conexion.query(
                                            `
                                                UPDATE abonos

                                                SET monto_abono = ?, metodo_pago = ?
                                                WHERE id_abono = ?
                                            `,
                                            [
                                                nuevoMonto,
                                                metodoPago,
                                                idAbono
                                            ],
                                            (
                                                errorActualizar,
                                                resultado
                                            ) => {

                                                if (errorActualizar) {

                                                    return conexion.rollback(
                                                        () => {

                                                            console.log(
                                                                "âŒ Error actualizando abono:",
                                                                errorActualizar
                                                            );

                                                            return res.status(500).json({
                                                                ok: false,
                                                                mensaje:
                                                                    "No se pudo actualizar el abono"
                                                            });

                                                        }
                                                    );

                                                }


                                                if (
                                                    resultado.affectedRows === 0
                                                ) {

                                                    return conexion.rollback(
                                                        () => {

                                                            return res.status(404).json({
                                                                ok: false,
                                                                mensaje:
                                                                    "Abono no encontrado"
                                                            });

                                                        }
                                                    );

                                                }


                                                // ======================================================
                                                // CONFIRMAR CAMBIO
                                                // ======================================================

                                                conexion.commit(
                                                    (errorCommit) => {

                                                        if (errorCommit) {

                                                            return conexion.rollback(
                                                                () => {

                                                                    console.log(
                                                                        "âŒ Error confirmando ediciÃ³n del abono:",
                                                                        errorCommit
                                                                    );

                                                                    return res.status(500).json({
                                                                        ok: false,
                                                                        mensaje:
                                                                            "No se pudo completar la ediciÃ³n del abono"
                                                                    });

                                                                }
                                                            );

                                                        }


                                                        return res.json({
                                                            ok: true,
                                                            mensaje:
                                                                "Su cambio ha sido guardado"
                                                        });

                                                    }
                                                );

                                            }
                                        );

                                    }
                                );

                            }
                        );

                    }
                );

            }
        );

    }
);
app.post('/delete-payment', protegerAdmin, (req, res) => {

    const idAbono = Number(req.body.id_abono);

    if (!Number.isInteger(idAbono) || idAbono <= 0) {
        return res.status(400).json({
            ok: false,
            mensaje: "Abono invalido"
        });
    }

    conexion.beginTransaction((errorTransaccion) => {

        if (errorTransaccion) {
            return res.status(500).json({
                ok: false,
                mensaje: "No se pudo iniciar la eliminacion"
            });
        }

        conexion.query(`
            SELECT
                a.id_abono,
                p.archivado
            FROM abonos a
            INNER JOIN pedidos p
                ON p.id_pedido = a.id_pedido
            WHERE a.id_abono = ?
            LIMIT 1
            FOR UPDATE
        `, [idAbono], (errorBuscar, resultados) => {

            if (errorBuscar) {
                return conexion.rollback(() => {
                    res.status(500).json({
                        ok: false,
                        mensaje: "No se pudo verificar el abono"
                    });
                });
            }

            if (!resultados || resultados.length === 0) {
                return conexion.rollback(() => {
                    res.status(404).json({
                        ok: false,
                        mensaje: "Abono no encontrado"
                    });
                });
            }

            if (Number(resultados[0].archivado) === 1) {
                return conexion.rollback(() => {
                    res.status(400).json({
                        ok: false,
                        mensaje: "No se pueden eliminar abonos de facturas archivadas"
                    });
                });
            }

            conexion.query(`
                DELETE FROM abonos
                WHERE id_abono = ?
            `, [idAbono], (errorEliminar, resultado) => {

                if (errorEliminar) {
                    return conexion.rollback(() => {
                        res.status(500).json({
                            ok: false,
                            mensaje: "No se pudo eliminar el abono"
                        });
                    });
                }

                if (resultado.affectedRows !== 1) {
                    return conexion.rollback(() => {
                        res.status(404).json({
                            ok: false,
                            mensaje: "Abono no encontrado"
                        });
                    });
                }

                conexion.commit((errorCommit) => {

                    if (errorCommit) {
                        return conexion.rollback(() => {
                            res.status(500).json({
                                ok: false,
                                mensaje: "No se pudo completar la eliminacion"
                            });
                        });
                    }

                    return res.json({
                        ok: true,
                        mensaje: "Abono eliminado correctamente"
                    });
                });
            });
        });
    });
});

app.post(
    '/add-payment',
    protegerAdmin,
    (req, res) => {

        const idPedido =
            Number(
                req.body.id_pedido
            );

        const montoAbono =
            Number(
                req.body.monto_abono
            );

        const metodoPago =
            String(
                req.body.metodo_pago || ''
            ).trim();


        /* =================================================
           VALIDAR DATOS
        ================================================= */

        if(
            !Number.isInteger(idPedido) ||
            idPedido <= 0 ||
            !Number.isFinite(montoAbono) ||
            montoAbono <= 0 ||
            !metodoPago
        ){

            return res
                .status(400)
                .json({
                    ok: false,
                    mensaje:
                        "Datos de abono invÃ¡lidos."
                });

        }


        conexion.beginTransaction(
            (errorTransaccion) => {

                if(errorTransaccion){

                    console.log(
                        "âŒ Error iniciando transacciÃ³n de abono:",
                        errorTransaccion
                    );

                    return res
                        .status(500)
                        .json({
                            ok: false,
                            mensaje:
                                "No se pudo iniciar el abono."
                        });

                }


                /* =================================================
                   BUSCAR LA FACTURA DEL PEDIDO
                ================================================= */

                conexion.query(
                    `
                        SELECT
                            id_pedido,
                            id_usuario,
                            grupo_compra,
                            archivado

                        FROM pedidos

                        WHERE id_pedido = ?

                        LIMIT 1
                    `,
                    [
                        idPedido
                    ],
                    (
                        errorPedido,
                        pedidos
                    ) => {

                        if(errorPedido){

                            return conexion.rollback(
                                () => {

                                    console.log(
                                        "âŒ Error buscando pedido:",
                                        errorPedido
                                    );

                                    return res
                                        .status(500)
                                        .json({
                                            ok: false,
                                            mensaje:
                                                "No se pudo verificar la factura."
                                        });

                                }
                            );

                        }


                        if(
                            !pedidos ||
                            pedidos.length === 0
                        ){

                            return conexion.rollback(
                                () => {

                                    return res
                                        .status(404)
                                        .json({
                                            ok: false,
                                            mensaje:
                                                "Factura no encontrada."
                                        });

                                }
                            );

                        }


                        const pedidoBase =
                            pedidos[0];


                        if(
                            Number(
                                pedidoBase.archivado
                            ) === 1
                        ){

                            return conexion.rollback(
                                () => {

                                    return res
                                        .status(400)
                                        .json({
                                            ok: false,
                                            mensaje:
                                                "No se pueden agregar abonos a una factura archivada."
                                        });

                                }
                            );

                        }


                        const idUsuario =
                            Number(
                                pedidoBase.id_usuario
                            );

                        const grupoCompra =
                            Number(
                                pedidoBase.grupo_compra
                            );


                        if(
                            !Number.isInteger(grupoCompra) ||
                            grupoCompra <= 0
                        ){

                            return conexion.rollback(
                                () => {

                                    return res
                                        .status(400)
                                        .json({
                                            ok: false,
                                            mensaje:
                                                "La factura seleccionada no tiene un grupo vÃ¡lido."
                                        });

                                }
                            );

                        }


                        /* =================================================
                           BUSCAR TODOS LOS PEDIDOS
                           DE ESTA FACTURA

                           TambiÃ©n los bloqueamos mientras
                           se registra el abono.
                        ================================================= */

                        conexion.query(
                            `
                                SELECT
    p.id_pedido,
    p.peso_gramos,
    p.total_precio,
    g.tarifa_envio_personalizada
FROM pedidos p
INNER JOIN grupos_compra g
    ON g.id_grupo = p.grupo_compra
WHERE p.id_usuario = ?
AND p.grupo_compra = ?
AND p.archivado = 0
FOR UPDATE
                            `,
                            [
                                idUsuario,
                                grupoCompra
                            ],
                            (
                                errorFactura,
                                pedidosFactura
                            ) => {

                                if(errorFactura){

                                    return conexion.rollback(
                                        () => {

                                            console.log(
                                                "âŒ Error buscando factura:",
                                                errorFactura
                                            );

                                            return res
                                                .status(500)
                                                .json({
                                                    ok: false,
                                                    mensaje:
                                                        "No se pudo verificar la factura."
                                                });

                                        }
                                    );

                                }


                                if(
                                    !pedidosFactura ||
                                    pedidosFactura.length === 0
                                ){

                                    return conexion.rollback(
                                        () => {

                                            return res
                                                .status(404)
                                                .json({
                                                    ok: false,
                                                    mensaje:
                                                        "Factura no encontrada."
                                                });

                                        }
                                    );

                                }


                                /* =================================================
                                   IDS DE TODOS LOS PEDIDOS
                                   DE ESTA FACTURA
                                ================================================= */

                                const idsPedidos =
                                    pedidosFactura.map(
                                        pedido =>
                                            pedido.id_pedido
                                    );


                                /* =================================================
                                   PESO GENERAL / ENVÃO GENERAL

                                   Normalmente el peso general
                                   estÃ¡ guardado en el primer pedido.

                                   Sumamos todos para mantener
                                   compatibilidad con registros anteriores.
                                ================================================= */

                                const pesoGeneral =
                                    pedidosFactura.reduce(
                                        (
                                            acumulado,
                                            pedido
                                        ) => {

                                            return acumulado +
                                                (
                                                    Number(
                                                        pedido.peso_gramos
                                                    ) || 0
                                                );

                                        },
                                        0
                                    );


                                const tarifaPersonalizada =
    pedidosFactura[0].tarifa_envio_personalizada;

const envioGeneral =
    tarifaPersonalizada !== null &&
    tarifaPersonalizada !== undefined &&
    tarifaPersonalizada !== ""
        ? Number(tarifaPersonalizada)
        : (pesoGeneral / 1000) * 6000;
                                const subtotalProductos =
    pedidosFactura.reduce(
        (
            acumulado,
            pedido
        ) => {

            return acumulado +
                (
                    Number(
                        pedido.total_precio
                    ) || 0
                );

        },
        0
    );


const totalFactura =
    subtotalProductos +
    envioGeneral;


                                /* =================================================
                                   SUMAR TODOS LOS ABONOS
                                   DE TODA LA FACTURA
                                ================================================= */

                                conexion.query(
                                    `
                                        SELECT
                                            IFNULL(
                                                SUM(monto_abono),
                                                0
                                            ) AS total_abonado

                                        FROM abonos

                                        WHERE id_pedido IN (?)
                                    `,
                                    [
                                        idsPedidos
                                    ],
                                    (
                                        errorAbonos,
                                        resultadosAbonos
                                    ) => {

                                        if(errorAbonos){

                                            return conexion.rollback(
                                                () => {

                                                    console.log(
                                                        "âŒ Error consultando abonos:",
                                                        errorAbonos
                                                    );

                                                    return res
                                                        .status(500)
                                                        .json({
                                                            ok: false,
                                                            mensaje:
                                                                "No se pudo verificar el saldo de la factura."
                                                        });

                                                }
                                            );

                                        }


                                        const totalAbonado =
                                            Number(
                                                resultadosAbonos[0]
                                                    .total_abonado
                                            ) || 0;


                                        const saldoPendiente =
                                            totalFactura -
                                            totalAbonado;


                                        /* =================================================
                                           FACTURA YA PAGADA
                                        ================================================= */

                                        if(
                                            saldoPendiente <= 0
                                        ){

                                            return conexion.rollback(
                                                () => {

                                                    return res
                                                        .status(400)
                                                        .json({
                                                            ok: false,
                                                            mensaje:
                                                                "Esta factura ya estÃ¡ completamente pagada."
                                                        });

                                                }
                                            );

                                        }


                                        /* =================================================
                                           NO PERMITIR ABONO
                                           MAYOR AL SALDO GENERAL
                                        ================================================= */

                                        if(
                                            montoAbono >
                                            saldoPendiente
                                        ){

                                            return conexion.rollback(
                                                () => {

                                                    return res
                                                        .status(400)
                                                        .json({
                                                            ok: false,
                                                            mensaje:
                                                                `El saldo pendiente de esta factura es â‚¡${saldoPendiente.toLocaleString('es-CR').replace(/[\u00A0\u202F ]/g, ".")}. No puede ingresar un abono mayor.`
                                                        });

                                                }
                                            );

                                        }


                                        /* =================================================
                                           FECHA COSTA RICA
                                        ================================================= */

                                        const fecha =
                                            new Intl.DateTimeFormat(
                                                'en-CA',
                                                {
                                                    timeZone:
                                                        'America/Costa_Rica',

                                                    year:
                                                        'numeric',

                                                    month:
                                                        '2-digit',

                                                    day:
                                                        '2-digit'
                                                }
                                            ).format(
                                                new Date()
                                            );


                                        /* =================================================
                                           GUARDAR ABONO

                                           Se guarda en el pedido recibido,
                                           pero financieramente pertenece
                                           a toda la factura.
                                        ================================================= */

                                        conexion.query(
                                            `
                                                INSERT INTO abonos
                                                (
                                                    id_pedido,
                                                    monto_abono,
                                                    fecha_abono,
                                                    metodo_pago
                                                )

                                                VALUES (?, ?, ?, ?)
                                            `,
                                            [
                                                idPedido,
                                                montoAbono,
                                                fecha,
                                                metodoPago
                                            ],
                                            (
                                                errorInsertar
                                            ) => {

                                                if(errorInsertar){

                                                    return conexion.rollback(
                                                        () => {

                                                            console.log(
                                                                "âŒ Error guardando abono:",
                                                                errorInsertar
                                                            );

                                                            return res
                                                                .status(500)
                                                                .json({
                                                                    ok: false,
                                                                    mensaje:
                                                                        "No se pudo guardar el abono."
                                                                });

                                                        }
                                                    );

                                                }


                                                conexion.commit(
                                                    (
                                                        errorCommit
                                                    ) => {

                                                        if(errorCommit){

                                                            return conexion.rollback(
                                                                () => {

                                                                    console.log(
                                                                        "âŒ Error confirmando abono:",
                                                                        errorCommit
                                                                    );

                                                                    return res
                                                                        .status(500)
                                                                        .json({
                                                                            ok: false,
                                                                            mensaje:
                                                                                "No se pudo completar el abono."
                                                                        });

                                                                }
                                                            );

                                                        }


                                                        return res.json({
                                                            ok: true,
                                                            mensaje:
                                                                "Abono guardado correctamente."
                                                        });

                                                    }
                                                );

                                            }
                                        );

                                    }
                                );

                            }
                        );

                    }
                );

            }
        );

    }
);
// ðŸ”¥ ACTUALIZAR PESO GENERAL
app.post(
    '/update-weight',
    protegerAdmin,
    (req, res) => {

        const idPedido =
            Number(
                req.body.id_pedido
            );

        const peso =
            Number(
                req.body.peso_gramos
            );


        if(
            !Number.isInteger(idPedido) ||
            idPedido <= 0 ||
            !Number.isFinite(peso) ||
            peso <= 0
        ){

            return res
                .status(400)
                .json({
                    ok: false,
                    mensaje:
                        "Datos de peso invÃ¡lidos"
                });

        }


        conexion.query(
            `
                UPDATE pedidos

                SET
                    peso_gramos = ?

                WHERE id_pedido = ?
            `,
            [
                peso,
                idPedido
            ],
            (
                err,
                resultado
            ) => {

                if(err){

                    console.log(
                        "âŒ Error actualizando peso:",
                        err
                    );

                    return res
                        .status(500)
                        .json({
                            ok: false,
                            mensaje:
                                "No se pudo actualizar el peso"
                        });

                }


                if(
                    resultado.affectedRows === 0
                ){

                    return res
                        .status(404)
                        .json({
                            ok: false,
                            mensaje:
                                "Pedido no encontrado"
                        });

                }


                return res.json({
                    ok: true,
                    mensaje:
                        "Peso actualizado correctamente"
                });

            }
        );

    }
);


// ðŸ”¹ CAMBIAR ESTADO
// ======================================================
// EDITAR TARIFA DE ENVIO DE UNA FACTURA
// ======================================================
app.post('/update-shipping-rate', protegerAdmin, (req, res) => {

    const idGrupo = Number(req.body.grupo_compra);
    const tarifa = Number(req.body.tarifa_envio_personalizada);

    if (
        !Number.isInteger(idGrupo) ||
        idGrupo <= 0 ||
        !Number.isFinite(tarifa) ||
        tarifa < 0
    ) {
        return res.status(400).json({
            ok: false,
            mensaje: "Datos de tarifa invalidos"
        });
    }

    conexion.query(
        `
        UPDATE grupos_compra
        SET tarifa_envio_personalizada = ?
        WHERE id_grupo = ?
        `,
        [tarifa, idGrupo],
        (err, resultado) => {

            if (err) {
                console.error("Error al editar tarifa:", err);

                return res.status(500).json({
                    ok: false,
                    mensaje: "No se pudo actualizar la tarifa"
                });
            }

            if (resultado.affectedRows === 0) {
                return res.status(404).json({
                    ok: false,
                    mensaje: "Factura no encontrada"
                });
            }

            return res.json({
                ok: true,
                mensaje: "Tarifa actualizada correctamente"
            });
        }
    );
});
app.post('/update-status',protegerAdmin,  (req, res) => {
    const { id_pedido, estado } = req.body;

    conexion.query(`
        UPDATE pedidos SET estado = ? WHERE id_pedido = ?
    `, [estado, id_pedido], (err) => {
        if (err) return res.send("Error âŒ");
        res.json({ ok: true });
    });
});

// ======================================================
// ðŸ”¹ ELIMINAR UN PEDIDO ACTIVO
// ======================================================

app.post('/delete-order', protegerAdmin, (req, res) => {

    const idPedido = Number(req.body.id_pedido);

    if (!idPedido) {
        return res.status(400).json({
            ok: false,
            mensaje: "Pedido invÃ¡lido"
        });
    }

    conexion.beginTransaction((errorTransaccion) => {

        if (errorTransaccion) {
            console.log(
                "âŒ Error iniciando eliminaciÃ³n:",
                errorTransaccion
            );

            return res.status(500).json({
                ok: false,
                mensaje: "No se pudo iniciar la eliminaciÃ³n"
            });
        }

        conexion.query(`
            DELETE FROM abonos
            WHERE id_pedido = ?
        `, [idPedido], (errorAbonos) => {

            if (errorAbonos) {

                return conexion.rollback(() => {

                    console.log(
                        "âŒ Error eliminando abonos:",
                        errorAbonos
                    );

                    return res.status(500).json({
                        ok: false,
                        mensaje: "No se pudieron eliminar los abonos"
                    });

                });
            }

            conexion.query(`
                DELETE FROM pedidos
                WHERE id_pedido = ?
                AND archivado = 0
            `, [idPedido], (errorPedido, resultado) => {

                if (errorPedido) {

                    return conexion.rollback(() => {

                        console.log(
                            "âŒ Error eliminando pedido:",
                            errorPedido
                        );

                        return res.status(500).json({
                            ok: false,
                            mensaje: "No se pudo eliminar el pedido"
                        });

                    });
                }

                if (resultado.affectedRows === 0) {

                    return conexion.rollback(() => {

                        return res.status(404).json({
                            ok: false,
                            mensaje: "Pedido activo no encontrado"
                        });

                    });
                }

                conexion.commit((errorCommit) => {

                    if (errorCommit) {

                        return conexion.rollback(() => {

                            console.log(
                                "âŒ Error confirmando eliminaciÃ³n:",
                                errorCommit
                            );

                            return res.status(500).json({
                                ok: false,
                                mensaje: "No se pudo completar la eliminaciÃ³n"
                            });

                        });
                    }

                    return res.json({
                        ok: true,
                        mensaje: "Pedido eliminado correctamente"
                    });

                });

            });

        });

    });

});

// ======================================================
// ðŸ”¹ ELIMINAR UNA FACTURA ARCHIVADA ESPECÃFICA
// ======================================================

app.post('/delete-archived-client-orders', protegerAdmin, (req, res) => {

    const idUsuario = Number(req.body.id_usuario);

    const grupoCompra =
        req.body.grupo_compra !== undefined &&
        req.body.grupo_compra !== null
            ? Number(req.body.grupo_compra)
            : null;

    const idPedido =
        req.body.id_pedido !== undefined &&
        req.body.id_pedido !== null
            ? Number(req.body.id_pedido)
            : null;


    if (
        !Number.isInteger(idUsuario) ||
        idUsuario <= 0
    ) {
        return res.status(400).json({
            ok: false,
            mensaje: "Cliente invÃ¡lido"
        });
    }


    /*
        Debe venir:
        - grupo_compra para una factura normal
        O
        - id_pedido para un pedido antiguo sin grupo
    */

    if (
        (
            !Number.isInteger(grupoCompra) ||
            grupoCompra <= 0
        ) &&
        (
            !Number.isInteger(idPedido) ||
            idPedido <= 0
        )
    ) {
        return res.status(400).json({
            ok: false,
            mensaje: "Factura o pedido invÃ¡lido"
        });
    }


    conexion.beginTransaction((errorTransaccion) => {

        if (errorTransaccion) {

            console.log(
                "âŒ Error iniciando transacciÃ³n:",
                errorTransaccion
            );

            return res.status(500).json({
                ok: false,
                mensaje: "No se pudo iniciar la eliminaciÃ³n"
            });
        }


        let consultaBuscar = "";
        let parametrosBuscar = [];


        /*
            =====================================================
            FACTURA NORMAL CON GRUPO
            =====================================================
        */

        if (
            Number.isInteger(grupoCompra) &&
            grupoCompra > 0
        ) {

            consultaBuscar = `
                SELECT id_pedido
                FROM pedidos
                WHERE id_usuario = ?
                AND grupo_compra = ?
                AND archivado = 1
            `;

            parametrosBuscar = [
                idUsuario,
                grupoCompra
            ];

        }

        /*
            =====================================================
            PEDIDO ANTIGUO SIN GRUPO
            =====================================================
        */

        else {

            consultaBuscar = `
                SELECT id_pedido
                FROM pedidos
                WHERE id_usuario = ?
                AND id_pedido = ?
                AND grupo_compra IS NULL
                AND archivado = 1
            `;

            parametrosBuscar = [
                idUsuario,
                idPedido
            ];
        }


        conexion.query(
            consultaBuscar,
            parametrosBuscar,
            (errorBuscar, pedidos) => {

                if (errorBuscar) {

                    return conexion.rollback(() => {

                        console.log(
                            "âŒ Error buscando factura archivada:",
                            errorBuscar
                        );

                        return res.status(500).json({
                            ok: false,
                            mensaje: "No se pudo buscar la factura archivada"
                        });

                    });
                }


                if (!pedidos || pedidos.length === 0) {

                    return conexion.rollback(() => {

                        return res.status(404).json({
                            ok: false,
                            mensaje: "No se encontrÃ³ la factura archivada seleccionada"
                        });

                    });
                }


                const idsPedidos =
                    pedidos.map(
                        pedido => pedido.id_pedido
                    );


                conexion.query(
                    `
                        DELETE FROM abonos
                        WHERE id_pedido IN (?)
                    `,
                    [idsPedidos],
                    (errorAbonos) => {

                        if (errorAbonos) {

                            return conexion.rollback(() => {

                                console.log(
                                    "âŒ Error eliminando abonos:",
                                    errorAbonos
                                );

                                return res.status(500).json({
                                    ok: false,
                                    mensaje: "No se pudieron eliminar los abonos"
                                });

                            });
                        }


                        conexion.query(
                            `
                                DELETE FROM pedidos
                                WHERE id_pedido IN (?)
                                AND archivado = 1
                            `,
                            [idsPedidos],
                            (errorPedidos, resultadoPedidos) => {

                                if (errorPedidos) {

                                    return conexion.rollback(() => {

                                        console.log(
                                            "âŒ Error eliminando pedidos:",
                                            errorPedidos
                                        );

                                        return res.status(500).json({
                                            ok: false,
                                            mensaje: "No se pudieron eliminar los pedidos"
                                        });

                                    });
                                }


                                /*
                                    Si era una factura con grupo,
                                    revisamos si el grupo quedÃ³ sin pedidos.
                                */

                                if (
                                    Number.isInteger(grupoCompra) &&
                                    grupoCompra > 0
                                ) {

                                    conexion.query(
                                        `
                                            SELECT COUNT(*) AS total
                                            FROM pedidos
                                            WHERE grupo_compra = ?
                                        `,
                                        [grupoCompra],
                                        (errorContar, resultadoContar) => {

                                            if (errorContar) {

                                                return conexion.rollback(() => {

                                                    console.log(
                                                        "âŒ Error revisando grupo:",
                                                        errorContar
                                                    );

                                                    return res.status(500).json({
                                                        ok: false,
                                                        mensaje: "No se pudo verificar el grupo"
                                                    });

                                                });
                                            }


                                            const totalRestante =
                                                Number(
                                                    resultadoContar[0].total
                                                ) || 0;


                                            if (totalRestante === 0) {

                                                conexion.query(
                                                    `
                                                        DELETE FROM grupos_compra
                                                        WHERE id_grupo = ?
                                                    `,
                                                    [grupoCompra],
                                                    (errorGrupo) => {

                                                        if (errorGrupo) {

                                                            return conexion.rollback(() => {

                                                                console.log(
                                                                    "âŒ Error eliminando grupo:",
                                                                    errorGrupo
                                                                );

                                                                return res.status(500).json({
                                                                    ok: false,
                                                                    mensaje: "No se pudo eliminar el grupo"
                                                                });

                                                            });
                                                        }


                                                        finalizarEliminacion();

                                                    }
                                                );

                                            } else {

                                                finalizarEliminacion();

                                            }

                                        }
                                    );

                                } else {

                                    finalizarEliminacion();

                                }


                                function finalizarEliminacion() {

                                    conexion.commit((errorCommit) => {

                                        if (errorCommit) {

                                            return conexion.rollback(() => {

                                                console.log(
                                                    "âŒ Error confirmando eliminaciÃ³n:",
                                                    errorCommit
                                                );

                                                return res.status(500).json({
                                                    ok: false,
                                                    mensaje: "No se pudo completar la eliminaciÃ³n"
                                                });

                                            });
                                        }


                                        return res.json({
                                            ok: true,
                                            eliminados:
                                                resultadoPedidos.affectedRows,
                                            mensaje:
                                                "Factura archivada eliminada correctamente"
                                        });

                                    });

                                }

                            }
                        );

                    }
                );

            }
        );

    });

});

// ðŸ” LÃMITE DE SOLICITUDES PARA RECUPERAR CONTRASEÃ‘A
const forgotPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 3, // mÃ¡ximo 3 solicitudes
    standardHeaders: true,
    legacyHeaders: false,
    message: "Demasiadas solicitudes de recuperaciÃ³n. Intente nuevamente en 15 minutos."
});


// ðŸ”¹ OLVIDÃ‰ CONTRASEÃ‘A
app.post('/forgot-password', forgotPasswordLimiter, (req, res) => {

    console.log("ðŸ“© EntrÃ³ una solicitud de recuperaciÃ³n");

    const correo = String(req.body.correo || '')
        .trim()
        .toLowerCase();

    const mensajeGenerico =
        "Si el correo estÃ¡ registrado, recibirÃ¡s un enlace para recuperar tu contraseÃ±a.";

    if (!correo) {
        return res
            .status(400)
            .send("Ingrese un correo electrÃ³nico");
    }

    // ðŸ”¹ COMPROBAR SI EL USUARIO EXISTE
    conexion.query(
        `SELECT id_usuario FROM usuarios WHERE correo = ? LIMIT 1`,
        [correo],
        (err, resultados) => {

            if (err) {
                console.log("âŒ Error buscando usuario:", err);

                return res
                    .status(500)
                    .send("Error del servidor");
            }

            // ðŸ” NO REVELAR SI EL CORREO EXISTE O NO
            if (resultados.length === 0) {

                console.log(
                    "â„¹ï¸ Solicitud recibida para un correo no registrado"
                );

                return res
                    .status(200)
                    .send(mensajeGenerico);
            }

            console.log("âœ… Solicitud de recuperaciÃ³n vÃ¡lida");

            // ðŸ”¹ GENERAR TOKEN
            const token =
                crypto.randomBytes(32).toString('hex');

            // ðŸ”¹ 15 MINUTOS
            const expiracion =
                Date.now() + (15 * 60 * 1000);

            // ðŸ”¹ GUARDAR TOKEN
            conexion.query(
                `
                UPDATE usuarios
                SET
                    reset_token = ?,
                    reset_expiration = ?
                WHERE correo = ?
                `,
                [token, expiracion, correo],
                async (errorToken) => {

                    if (errorToken) {

                        console.log(
                            "âŒ Error guardando token:",
                            errorToken
                        );

                        return res
                            .status(500)
                            .send("Error del servidor");
                    }

                    console.log(
                        "âœ… Token guardado correctamente"
                    );

                    // ðŸ”¹ LINK DE RECUPERACIÃ“N
                    /*const link =
                        `http://localhost:3000/reset-password/${token}`;
                    */

                    const BASE_URL = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

                    const link = `${BASE_URL}/reset-password/${token}`;

                    console.log(
                        "ðŸ“¤ Intentando enviar correo..."
                    );

                    try {
const { data, error } =
    await resend.emails.send({

        from:
            'Tienda Ana <onboarding@resend.dev>',

        to:
            correo,

        subject:
            'Recuperar contraseÃ±a - Tienda Ana',

        html: `
            <div style="
                font-family: Arial, sans-serif;
                max-width: 500px;
                margin: auto;
                padding: 25px;
                border: 1px solid #eeeeee;
                border-radius: 10px;
            ">

                <h2 style="
                    color: #c48b9f;
                    text-align: center;
                ">
                    Tienda Ana Compras
                </h2>

                <p>
                    Recibimos una solicitud para cambiar tu contraseÃ±a.
                </p>

                <p>
                    Presiona el siguiente botÃ³n para crear una nueva contraseÃ±a:
                </p>

                <div style="
                    text-align: center;
                    margin: 30px 0;
                ">

                    <a
                        href="${link}"
                        style="
                            background: #c48b9f;
                            color: white;
                            padding: 12px 20px;
                            text-decoration: none;
                            border-radius: 8px;
                            font-weight: bold;
                        "
                    >
                        Cambiar contraseÃ±a
                    </a>

                </div>

                <p>
                    Este enlace tiene una duraciÃ³n de 15 minutos.
                </p>

                <p style="
                    color: #777777;
                    font-size: 13px;
                ">
                    Si no solicitaste este cambio,
                    puedes ignorar este correo.
                </p>

            </div>
        `
    });

if (error) {
    throw error;
}

console.log(
    "âœ… CORREO DE RECUPERACIÃ“N ENVIADO:",
    data.id
);

                        return res
                            .status(200)
                            .send(mensajeGenerico);

                    } catch (errorCorreo) {

                        console.log(
                            "âŒ ERROR ENVIANDO RECUPERACIÃ“N:"
                        );

                        console.log(errorCorreo);

                        // ðŸ” NO REVELAR INFORMACIÃ“N AL USUARIO
                        return res
                            .status(200)
                            .send(mensajeGenerico);
                    }
                }
            );
        }
    );
});

// ðŸ”¥ RESET PASSWORD (BONITO)
// ======================================================
// ðŸ”¥ PÃGINA PARA CAMBIAR CONTRASEÃ‘A
// ======================================================

function paginaNuevaPassword(token, mensaje = "", tipo = "") {

    let mensajeHTML = "";

    if (mensaje) {

        const clase =
            tipo === "ok"
                ? "mensaje exito"
                : "mensaje error";

        mensajeHTML = `
            <div class="${clase}">
                ${mensaje}
            </div>
        `;
    }

    return `
    <!DOCTYPE html>
    <html lang="es">

    <head>

     

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <title>Cambiar contraseÃ±a - Tienda Ana</title>

        <style>

            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                min-height: 100vh;

                font-family:
                    'Segoe UI',
                    Tahoma,
                    Geneva,
                    Verdana,
                    sans-serif;

                background:
                    linear-gradient(
                        to right,
                        #f8e1e7,
                        #fdf6f0
                    );

                display: flex;
                justify-content: center;
                align-items: center;

                padding: 20px;
            }


            .contenedor {

                width: 100%;
                max-width: 430px;

                text-align: center;
            }


            .encabezado {

                margin-bottom: 20px;
            }


            .encabezado h1 {

                color: #c48b9f;

                margin:
                    0 0 12px 0;

                font-size: 28px;
            }


            .logo {

                width: 90px;
                height: 90px;

                object-fit: contain;

                border-radius: 12px;
            }


            .tarjeta {

                background: white;

                border-radius: 16px;

                padding:
                    35px 30px;

                box-shadow:
                    0 8px 25px
                    rgba(0, 0, 0, 0.15);
            }


            .icono {

                width: 60px;
                height: 60px;

                margin:
                    0 auto 15px;

                border-radius: 50%;

                background: #f8e1e7;

                display: flex;
                justify-content: center;
                align-items: center;

                font-size: 28px;
            }


            h2 {

                margin:
                    0 0 10px;

                color: #333;

                font-size: 24px;
            }


            .descripcion {

                color: #777;

                font-size: 14px;

                line-height: 1.5;

                margin-bottom: 24px;
            }


            input {

                width: 100%;

                padding: 13px 14px;

                margin-bottom: 14px;

                border:
                    1px solid #ddd;

                border-radius: 8px;

                font-size: 14px;

                outline: none;

                transition: 0.2s;
            }


            input:focus {

                border-color:
                    #c48b9f;

                box-shadow:
                    0 0 0 3px
                    rgba(196, 139, 159, 0.15);
            }


            /* ========================================
               ðŸ” REQUISITOS DE CONTRASEÃ‘A
            ======================================== */

            .password-requisitos {

                display: none;

                margin:
                    -5px 0 14px 0;

                color: #c62828;

                font-size: 13px;

                line-height: 1.4;

                text-align: left;
            }


            button {

                width: 100%;

                padding: 13px;

                margin-top: 5px;

                border: none;

                border-radius: 8px;

                background: #c48b9f;

                color: white;

                font-size: 15px;

                font-weight: bold;

                cursor: pointer;

                transition: 0.2s;
            }


            button:hover {

                background: #b3748a;
            }


            .mensaje {

                width: 100%;

                padding: 14px 16px;

                margin-bottom: 22px;

                border-radius: 8px;

                font-size: 14px;

                line-height: 1.5;

                text-align: left;
            }


            .mensaje.exito {

                background: #edf8f0;

                border:
                    1px solid #b9e2c2;

                color: #2f7041;
            }


            .mensaje.error {

                background: #fff0f0;

                border:
                    1px solid #f1bebe;

                color: #a94442;
            }


            .mensaje a {

                color: #c48b9f;

                font-weight: bold;

                text-decoration: underline;
            }


            .volver {

                display: inline-block;

                margin-top: 22px;

                color: #c48b9f;

                font-size: 14px;

                text-decoration: underline;

                font-weight: 600;
            }


            .volver:hover {

                color: #b3748a;
            }


            .seguridad {

                margin-top: 20px;

                color: #999;

                font-size: 12px;

                line-height: 1.5;
            }
/* ========================================
   ðŸ” MODAL CONFIRMAR CAMBIO CONTRASEÃ‘A
======================================== */

.modal-confirmacion {

    display: none;

    position: fixed;

    top: 0;
    left: 0;

    width: 100%;
    height: 100%;

    background:
        rgba(0, 0, 0, 0.45);

    justify-content: center;
    align-items: center;

    padding: 20px;

    z-index: 9999;
}


.modal-confirmacion.activo {

    display: flex;
}


.modal-contenido {

    width: 100%;
    max-width: 380px;

    background: white;

    border-radius: 16px;

    padding: 26px 28px;

    text-align: center;

    box-shadow:
        0 10px 30px
        rgba(0, 0, 0, 0.20);

    animation:
        aparecerModal 0.2s ease;
}


.modal-icono {

    width: 54px;
    height: 54px;

    margin: 0 auto 14px;

    border-radius: 50%;

    background: #f8e1e7;

    display: flex;
    align-items: center;
    justify-content: center;

    font-size: 24px;
}

.modal-contenido h3 {

    margin:
        0 0 14px;

    color: #333;

    font-size: 22px;
}


.modal-contenido p {

    margin:
        0 0 22px;

    color: #666;

    font-size: 14px;

    line-height: 1.6;
}

.modal-botones {

    display: flex;

    justify-content: center;

    gap: 10px;

    margin-top: 20px;
}


.modal-botones button {

    width: auto;

    min-width: 110px;

    padding: 10px 18px;

    margin: 0;

    border-radius: 8px;

    font-size: 14px;
}

.btn-cancelar {

    background: #e5e5e5;

    color: #333;
}


.btn-cancelar:hover {

    background: #d8d8d8;
}


.btn-confirmar {

    background: #c48b9f;

    color: white;
}


.btn-confirmar:hover {

    background: #b3748a;
}


@keyframes aparecerModal {

    from {

        opacity: 0;

        transform:
            scale(0.96);
    }

    to {

        opacity: 1;

        transform:
            scale(1);
    }
}

            @media(max-width: 480px) {

                .tarjeta {

                    padding:
                        28px 20px;
                }


                .encabezado h1 {

                    font-size: 24px;
                }

            }

        </style>

    </head>


    <body>


        <div class="contenedor">


            <div class="encabezado">

                <h1>
                    Tienda Ana Compras ðŸ›ï¸
                </h1>

                <img
                    src="/logo.jpg"
                    alt="Logo Tienda Ana"
                    class="logo"
                >

            </div>


            <div class="tarjeta">


                ${mensajeHTML}

            <div
             id="zonaCambioPassword"
             style="${token ? '' : 'display:none;'}"
>
                <div class="icono">
                    ðŸ”
                </div>


                <h2>
                    Nueva contraseÃ±a
                </h2>


                <p class="descripcion">

                    Cree una nueva contraseÃ±a
                    para ingresar nuevamente
                    a su cuenta.

                </p>


                <form
                    method="POST"
                    action="/reset-password/${token}"
                    id="formNuevaPassword"
                >


                    <input
                        type="password"
                        name="password"
                        id="nuevaPassword"
                        placeholder="Nueva contraseÃ±a"
                        autocomplete="new-password"
                        minlength="8"
                        required
                    >


                    <div
                        id="passwordRequisitos"
                        class="password-requisitos"
                    >
                        âš ï¸ La contraseÃ±a debe tener mÃ­nimo
                        8 caracteres, al menos una letra
                        y un nÃºmero.
                    </div>


                    <input
                        type="password"
                        name="confirm"
                        placeholder="Confirmar contraseÃ±a"
                        autocomplete="new-password"
                        required
                    >


                    <button type="submit">

                        Confirmar contraseÃ±a

                    </button>


                </form>

<!-- ========================================
     ðŸ” MODAL CONFIRMAR CAMBIO CONTRASEÃ‘A
======================================== -->

<div
    id="modalConfirmacion"
    class="modal-confirmacion"
>

    <div class="modal-contenido">

        <div class="modal-icono">
            ðŸ”
        </div>

     <h3>
    Confirmar cambio
</h3>

<p>
    Por seguridad, la contraseÃ±a solo puede
    cambiarse una vez cada 24 horas.

    <br><br>

    <strong>
        Â¿Desea continuar?
    </strong>
</p>

        <div class="modal-botones">

            <button
                type="button"
                id="btnCancelarCambio"
                class="btn-cancelar"
            >
                Cancelar
            </button>

            <button
                type="button"
                id="btnConfirmarCambio"
                class="btn-confirmar"
            >
                Confirmar
            </button>

        </div>

    </div>

</div>

                <div class="seguridad">

                    ðŸ”’ Por seguridad,
                    el enlace de recuperaciÃ³n
                    tiene una duraciÃ³n limitada.

                </div>


            </div>


        </div>


        <script>

            // ========================================
            // ðŸ” VALIDAR CONTRASEÃ‘A MIENTRAS ESCRIBE
            // ========================================

            const passwordInput =
                document.getElementById(
                    "nuevaPassword"
                );

            const passwordRequisitos =
                document.getElementById(
                    "passwordRequisitos"
                );

            const formNuevaPassword =
                document.getElementById(
                    "formNuevaPassword"
                );


            function validarPassword(password) {

                const tieneLongitud =
                    password.length >= 8;

                const tieneLetra =
                    /[A-Za-z]/.test(password);

                const tieneNumero =
                    /\\d/.test(password);


                return (
                    tieneLongitud &&
                    tieneLetra &&
                    tieneNumero
                );

            }


            passwordInput.addEventListener(
                "input",
                () => {

                    const password =
                        passwordInput.value;


                    // Si estÃ¡ vacÃ­o, ocultar mensaje

                    if (password.length === 0) {

                        passwordRequisitos.style.display =
                            "none";

                        return;
                    }


                    // Si no cumple, mostrar mensaje rojo

                    if (!validarPassword(password)) {

                        passwordRequisitos.style.display =
                            "block";

                    } else {

                        // Si ya cumple, ocultar mensaje

                        passwordRequisitos.style.display =
                            "none";

                    }

                }
            );


     // ========================================
// ðŸ” ELEMENTOS DEL MODAL
// ========================================

const modalConfirmacion =
    document.getElementById(
        "modalConfirmacion"
    );

const btnCancelarCambio =
    document.getElementById(
        "btnCancelarCambio"
    );

const btnConfirmarCambio =
    document.getElementById(
        "btnConfirmarCambio"
    );


// ========================================
// ðŸ” ABRIR MODAL AL ENVIAR FORMULARIO
// ========================================

formNuevaPassword.addEventListener(
    "submit",
    (e) => {

        if (
            !validarPassword(
                passwordInput.value
            )
        ) {

            e.preventDefault();

            passwordRequisitos.style.display =
                "block";

            passwordInput.focus();

            return;
        }

        e.preventDefault();

        modalConfirmacion.classList.add(
            "activo"
        );

    }
);


// ========================================
// ðŸ”¹ CANCELAR CAMBIO
// ========================================

btnCancelarCambio.addEventListener(
    "click",
    () => {

        modalConfirmacion.classList.remove(
            "activo"
        );

    }
);


// ========================================
// âœ… CONFIRMAR CAMBIO
// ========================================

btnConfirmarCambio.addEventListener(
    "click",
    () => {

        modalConfirmacion.classList.remove(
            "activo"
        );

        formNuevaPassword.submit();

    }
);

 </script>


    </body>

    </html>
    `;
}


// ======================================================
// ======================================================
// ðŸ”¥ MOSTRAR CAMBIO DE CONTRASEÃ‘A
// ======================================================

app.get('/reset-password/:token', (req, res) => {

    const token =
        String(req.params.token || '').trim();


    // ============================================
    // ðŸ” VALIDAR FORMATO DEL TOKEN
    // ============================================

    const tokenValido =
        /^[a-f0-9]{64}$/.test(token);

    if (!tokenValido) {

        console.log(
            "âš ï¸ Intento de recuperaciÃ³n con token invÃ¡lido"
        );

        return res.send(
            paginaNuevaPassword(
                "",
                `
                âš ï¸ Este enlace es invÃ¡lido
                o estÃ¡ daÃ±ado.
                Solicite una nueva recuperaciÃ³n
                de contraseÃ±a.

                <br><br>

                Puede volver al
                <a href="/login.html">
                    inicio
                </a>.
                `,
                "error"
            )
        );
    }


    // ============================================
    // ðŸ”¹ COMPROBAR TOKEN EN LA BASE DE DATOS
    // ============================================

    conexion.query(`
        SELECT id_usuario
        FROM usuarios

        WHERE reset_token = ?
        AND reset_expiration > ?

        LIMIT 1
    `,
    [
        token,
        Date.now()
    ],
    (err, results) => {


        if (err) {

            console.log(
                "âŒ Error comprobando token:",
                err
            );

            return res.send(
                paginaNuevaPassword(
                    "",
                    `
                    âŒ No fue posible verificar
                    el enlace de recuperaciÃ³n.
                    `,
                    "error"
                )
            );
        }


        if (results.length === 0) {

            return res.send(
                paginaNuevaPassword(
                    "",
                    `
                    âš ï¸ Este enlace es invÃ¡lido
                    o ya expirÃ³.
                    Solicite una nueva recuperaciÃ³n
                    de contraseÃ±a.

                    <br><br>

                    Puede volver al
                    <a href="/login.html">
                        inicio
                    </a>.
                    `,
                    "error"
                )
            );
        }


        res.send(
            paginaNuevaPassword(
                token
            )
        );

    });

});



// ======================================================
// ðŸ”¥ GUARDAR NUEVA CONTRASEÃ‘A
// ======================================================

app.post('/reset-password/:token', (req, res) => {

    const token =
        String(req.params.token || '').trim();


    // ============================================
    // ðŸ” VALIDAR FORMATO DEL TOKEN
    // ============================================

    const tokenValido =
        /^[a-f0-9]{64}$/.test(token);

    if (!tokenValido) {

        console.log(
            "âš ï¸ Intento de cambio con token invÃ¡lido"
        );

        return res.send(
            paginaNuevaPassword(
                "",
                `
                âš ï¸ Este enlace de recuperaciÃ³n
                es invÃ¡lido o estÃ¡ daÃ±ado.

                <br><br>

                Solicite una nueva recuperaciÃ³n
                de contraseÃ±a.

                <br><br>

                Puede volver al
                <a href="/login.html">
                    inicio
                </a>.
                `,
                "error"
            )
        );
    }


    const {
        password,
        confirm
    } = req.body;



    // ============================================
    // ðŸ”¹ VALIDAR CAMPOS
    // ============================================

    if (!password || !confirm) {

        return res.send(
            paginaNuevaPassword(
                token,
                `
                âš ï¸ Complete ambos campos
                para continuar.
                `,
                "error"
            )
        );
    }



    // ============================================
    // ðŸ” VALIDAR SEGURIDAD DE LA CONTRASEÃ‘A
    // ============================================

    const passwordValido =
        /^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(password);

    if (!passwordValido) {

        return res.send(
            paginaNuevaPassword(
                token,
                `
                âš ï¸ La contraseÃ±a debe tener
                al menos 8 caracteres,
                una letra y un nÃºmero.
                `,
                "error"
            )
        );
    }



    // ============================================
    // ðŸ”¹ VALIDAR QUE COINCIDAN
    // ============================================

    if (password !== confirm) {

        return res.send(
            paginaNuevaPassword(
                token,
                `
                âš ï¸ Las contraseÃ±as
                no coinciden.
                IntÃ©ntelo nuevamente.
                `,
                "error"
            )
        );
    }



    // ============================================
    // ðŸ”¹ COMPROBAR TOKEN ANTES DE CAMBIAR
    // ============================================

    conexion.query(`
        SELECT
            id_usuario,
             ultimo_cambio_password

        FROM usuarios

        WHERE reset_token = ?
        AND reset_expiration > ?

        LIMIT 1
    `,
    [
        token,
        Date.now()
    ],
    async (err, results) => {


        if (err) {

            console.log(
                "âŒ Error comprobando token:",
                err
            );

            return res.send(
                paginaNuevaPassword(
                    token,
                    `
                    âŒ OcurriÃ³ un error
                    al verificar la recuperaciÃ³n.
                    `,
                    "error"
                )
            );
        }


        if (results.length === 0) {

            return res.send(
                paginaNuevaPassword(
                    "",
                    `
                    âš ï¸ El enlace de recuperaciÃ³n
                    es invÃ¡lido o ya expirÃ³.

                    <br><br>

                    Puede volver al
                    <a href="/login.html">
                        inicio
                    </a>.
                    `,
                    "error"
                )
            );
        }

// ============================================
// ðŸ” LIMITAR CAMBIO DE CONTRASEÃ‘A A 1 CADA 24 HORAS
// ============================================

const ultimoCambio = results[0].ultimo_cambio_password;

if (ultimoCambio) {

    const ahora = new Date();
    const ultimoCambioFecha = new Date(ultimoCambio);

    const diferencia =
        ahora.getTime() - ultimoCambioFecha.getTime();

    const veinticuatroHoras =
        24 * 60 * 60 * 1000;

    if (diferencia < veinticuatroHoras) {

        const tiempoRestante =
            veinticuatroHoras - diferencia;

        const horasRestantes =
            Math.ceil(
                tiempoRestante / (60 * 60 * 1000)
            );

        return res.send(
            paginaNuevaPassword(
                "",
                `
                ðŸ”’ Por seguridad, solo puede cambiar
                su contraseÃ±a una vez cada 24 horas.

                <br><br>

                PodrÃ¡ volver a cambiarla
                aproximadamente en
                <strong>${horasRestantes} hora(s)</strong>.

                <br><br>

                Puede volver al
                <a href="/login.html">
                    inicio
                </a>.
                `,
                "error"
            )
        );
    }
}

        try {


            // ============================================
            // ðŸ”¹ ENCRIPTAR NUEVA CONTRASEÃ‘A
            // ============================================

            const hash =
                await bcrypt.hash(
                    password,
                    10
                );



            // ============================================
            // ðŸ”¹ GUARDAR NUEVA CONTRASEÃ‘A
            // ============================================

            conexion.query(`
                UPDATE usuarios

                SET
                    password = ?,
                    reset_token = NULL,
                    reset_expiration = NULL,
                    ultimo_cambio_password = NOW()

                WHERE reset_token = ?
                AND reset_expiration > ?
            `,
            [
                hash,
                token,
                Date.now()
            ],
            (errorActualizar, resultado) => {


                if (errorActualizar) {

                    console.log(
                        "âŒ Error actualizando contraseÃ±a:",
                        errorActualizar
                    );

                    return res.send(
                        paginaNuevaPassword(
                            token,
                            `
                            âŒ No fue posible
                            actualizar la contraseÃ±a.
                            IntÃ©ntelo nuevamente.
                            `,
                            "error"
                        )
                    );
                }



                if (
                    resultado.affectedRows === 0
                ) {

                    return res.send(
                        paginaNuevaPassword(
                            "",
                            `
                            âš ï¸ No fue posible
                            actualizar la contraseÃ±a.
                            El enlace puede haber expirado.
                            `,
                            "error"
                        )
                    );
                }



                // ============================================
                // ðŸ”¹ MISMA PÃGINA + MENSAJE ARRIBA
                // ============================================

                return res.send(
                    paginaNuevaPassword(
                        "",
                        `
                        âœ… Su contraseÃ±a ha sido
                        actualizada correctamente.

                        <br><br>

                        Puede volver al
                        <a href="/login.html">
                            inicio
                        </a>
                        para iniciar sesiÃ³n.
                        `,
                        "ok"
                    )
                );


            });


        } catch (errorHash) {


            console.log(
                "âŒ Error preparando contraseÃ±a:",
                errorHash
            );


            return res.send(
                paginaNuevaPassword(
                    token,
                    `
                    âŒ No fue posible
                    actualizar la contraseÃ±a.
                    `,
                    "error"
                )
            );


        }


    });

});


// ðŸ”¥ SERVER
/*app.listen(3000, () => {
    console.log('ðŸš€ http://localhost:3000');
});*/

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`ðŸš€ http://localhost:${PORT}`);
});



