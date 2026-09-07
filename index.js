require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const MySQLStore = require('express-mysql-session')(session);
const sessionStore = new MySQLStore({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});
const app = express();
app.set('trust proxy', 1);

app.use(session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 8
    }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🔐 PROTECCIÓN PARA SUPERADMIN Y ADMIN
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
            .send('Acceso no autorizado ❌');
    }

    next();
}
// 🔐 PROTECCIÓN PARA CLIENTE
function protegerCliente(req, res, next) {

    if (!req.session.usuario) {
        return res.redirect('/login.html');
    }

    if (req.session.usuario.tipo_usuario !== 'cliente') {
        return res
            .status(403)
            .send('Acceso no autorizado ❌');
    }

    next();
}

// 🔐 PROTEGER DASHBOARD
app.get('/dashboard.html', protegerAdmin, (req, res) => {

    res.sendFile(
        path.join(__dirname, 'public', 'dashboard.html')
    );
});
// 🔐 PROTEGER PÁGINA DEL CLIENTE
app.get('/client.html', protegerCliente, (req, res) => {

    res.sendFile(
        path.join(__dirname, 'public', 'client.html')
    );
});

// 🔐 PROTEGER PÁGINAS ADMINISTRATIVAS
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



// 🔹 CONEXIÓN MYSQL 
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
        console.log('❌ Error de conexión:', err);
        return;
    }
    console.log('✅ Conectado a MySQL');
});

// 🔥 CORREO
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

// 🔹 INICIO
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// ======================================================
// 🔐 LÍMITE DE INTENTOS DE REGISTRO
// ======================================================

const registerLimiter = rateLimit({

    windowMs: 15 * 60 * 1000, // 15 minutos

    max: 5, // máximo 5 solicitudes

    standardHeaders: true,

    legacyHeaders: false,

    message:
        "Demasiados intentos de registro. Intente nuevamente en 15 minutos."

});



// ======================================================
// 🔹 REGISTRO
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
        // 🔐 NORMALIZAR DATOS
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
        // 🔐 VALIDAR CAMPOS OBLIGATORIOS
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
        // 🔐 VALIDAR NOMBRE Y APELLIDO
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
        // 🔐 VALIDAR TELÉFONO
        // ============================================

        const telefonoValido =
            /^[0-9+\-\s()]{8,20}$/.test(
                telefonoNormalizado
            );

        if (!telefonoValido) {

            return res.status(400).send(
                "Ingrese un número de teléfono válido."
            );

        }


        // ============================================
        // 🔐 VALIDAR CORREO
        // ============================================

        const correoValido =
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
                correoNormalizado
            );

        if (!correoValido) {

            return res.status(400).send(
                "Ingrese un correo electrónico válido."
            );

        }


        // ============================================
        // 🔐 VALIDAR PROVINCIA
        // ============================================

        const provinciasValidas = [
            "San José",
            "Alajuela",
            "Cartago",
            "Heredia",
            "Guanacaste",
            "Puntarenas",
            "Limón"
        ];

        if (
            !provinciasValidas.includes(
                provinciaNormalizada
            )
        ) {

            return res.status(400).send(
                "Seleccione una provincia válida."
            );

        }


        // ============================================
        // 🔐 VALIDAR CAMPOS DE DIRECCIÓN
        // ============================================

        if (
            cantonNormalizado.length > 100 ||
            distritoNormalizado.length > 100 ||
            direccionNormalizada.length > 255
        ) {

            return res.status(400).send(
                "Uno de los datos de dirección es demasiado largo."
            );

        }


        // ============================================
        // 🔐 VALIDAR CONTRASEÑA
        // ============================================

        const passwordValido =
            typeof password === 'string' &&
            /^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(password);


        if (!passwordValido) {

            return res.status(400).send(
                "La contraseña debe tener mínimo 8 caracteres, al menos una letra y un número."
            );

        }


        // ============================================
        // 🔐 COMPROBAR SI EL CORREO YA EXISTE
        // ============================================

        conexion.query(
            `
            SELECT id_usuario
            FROM usuarios
            WHERE LOWER(TRIM(correo)) = ?
            LIMIT 1
            `,
            [correoNormalizado],
            async (errorBuscar, resultados) => {


                if (errorBuscar) {

                    console.log(
                        "❌ Error verificando correo:",
                        errorBuscar
                    );

                    return res.status(500).send(
                        "Error ❌"
                    );

                }


                // ============================================
                // 🔐 CORREO YA REGISTRADO
                // ============================================

                if (resultados.length > 0) {

                    return res.status(409).send(
                        "Este correo ya está registrado. Inicie sesión o recupere su contraseña."
                    );

                }


                try {


                    // ============================================
                    // 🔐 ENCRIPTAR CONTRASEÑA
                    // ============================================

                    const hash =
                        await bcrypt.hash(
                            password,
                            10
                        );


                    // ============================================
                    // 🔹 GUARDAR USUARIO
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
                                    "❌ Error registrando usuario:",
                                    err
                                );

                                return res.status(500).send(
                                    "Error ❌"
                                );

                            }


                            return res.send(`
                                <h2 style="text-align:center;color:green;">
                                    ✅ Registrado correctamente
                                </h2>
                            `);

                        }
                    );


                } catch (errorHash) {

                    console.log(
                        "❌ Error preparando contraseña:",
                        errorHash
                    );

                    return res.status(500).send(
                        "Error ❌"
                    );

                }


            }
        );


    } catch (error) {

        console.log(
            "❌ Error en registro:",
            error
        );

        return res.status(500).send(
            "Error ❌"
        );

    }

});
// 🔐 LÍMITE DE INTENTOS DE LOGIN

const loginLimiter = rateLimit({

    windowMs: 15 * 60 * 1000, // 15 minutos

    max: 5, // máximo 5 intentos fallidos

    standardHeaders: true,

    legacyHeaders: false,

    // 🔐 Los inicios de sesión correctos no cuentan
    skipSuccessfulRequests: true,

    message: "Demasiados intentos de inicio de sesión. Intente nuevamente en 15 minutos."

});

// 🔹 LOGIN
app.post('/login', loginLimiter, (req, res) => {

    const { correo, password } = req.body;

    conexion.query(
        "SELECT * FROM usuarios WHERE correo = ?",
        [correo],
        async (err, results) => {

            if (err) {
                return res
                    .status(500)
                    .send("Error del servidor ❌");
            }

            if (results.length === 0) {
                return res
                    .status(401)
                    .send("Usuario o contraseña incorrectos ❌");
            }

            const usuario = results[0];

            const ok = await bcrypt.compare(
                password,
                usuario.password
            );

            if (!ok) {
                return res
                    .status(401)
                    .send("Usuario o contraseña incorrectos ❌");
            }

            // 🔐 CREAR UNA SESIÓN NUEVA DESPUÉS DEL LOGIN
            req.session.regenerate((err) => {

                if (err) {
                    console.log(
                        "❌ Error regenerando sesión:",
                        err
                    );

                    return res
                        .status(500)
                        .send("No se pudo iniciar sesión");
                }

                // 🔐 GUARDAR DATOS DEL USUARIO EN LA NUEVA SESIÓN
                req.session.usuario = {
                    id_usuario: usuario.id_usuario,
                    tipo_usuario: usuario.tipo_usuario,
                    nombre: usuario.nombre
                };

                req.session.save((err) => {

                    if (err) {
                        console.log(
                            "❌ Error guardando sesión:",
                            err
                        );

                        return res
                            .status(500)
                            .send("No se pudo iniciar sesión");
                    }

                    // 👤 CLIENTE
                    if (usuario.tipo_usuario === 'cliente') {

                        return res.redirect(
                            `/client.html?id=${usuario.id_usuario}`
                        );
                    }

                    // 👑 SUPERADMIN / ADMIN
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

// 🔐 CERRAR SESIÓN
app.get('/logout', (req, res) => {

    req.session.destroy((err) => {

        if (err) {
            console.log('❌ Error cerrando sesión:', err);

            return res
                .status(500)
                .send('No se pudo cerrar la sesión');
        }

        res.clearCookie('connect.sid');

        return res.redirect('/login.html');
    });
});



// 🔹 CLIENTES
app.get('/clientes', protegerAdmin, (req, res) => {
    conexion.query(`
        SELECT
            MIN(id_usuario) AS id_usuario,
            nombre,
            apellido
        FROM usuarios
        WHERE tipo_usuario = 'cliente'
        GROUP BY
            LOWER(TRIM(nombre)),
            LOWER(TRIM(apellido)),
            nombre,
            apellido
        ORDER BY nombre ASC, apellido ASC
    `, (err, results) => {

        if (err) {
            console.log("❌ Error cargando clientes:", err);
            return res.json([]);
        }

        res.json(results);
    });
});


// 🔹 ARTÍCULOS
// Carga los artículos guardados en el catálogo.
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
            console.log("❌ Error cargando artículos:", err);
            return res.json([]);
        }

        res.json(results);

    });

});


// 🔹 CREAR ARTÍCULO
app.post('/create-article',protegerAdmin, (req, res) => {

    const {
        nombre,
        tasa,
        descripcion
    } = req.body;

    if (!nombre || String(nombre).trim() === '') {
        return res.status(400).json({
            ok: false,
            mensaje: "Nombre de artículo requerido"
        });
    }

    const nombreLimpio =
        String(nombre).trim();

    const tasaNumero =
        Number(tasa) || 0;

    const descripcionLimpia =
        String(descripcion || '').trim();


    // Primero revisamos si ya existe el mismo nombre.
    conexion.query(`
        SELECT id_articulo
        FROM articulos
        WHERE LOWER(TRIM(nombre)) = LOWER(TRIM(?))
        LIMIT 1
    `, [nombreLimpio], (err, resultados) => {

        if (err) {
            console.log("❌ Error buscando artículo:", err);
            return res.status(500).json({
                ok: false
            });
        }

        if (resultados.length > 0) {

            return res.status(409).json({
                ok: false,
                mensaje: "El artículo ya existe"
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
                console.log("❌ Error guardando artículo:", err);
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
// 🔹 ACTUALIZAR ARTÍCULO
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
            mensaje:"Datos inválidos"
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
                "❌ Error actualizando artículo:",
                err
            );

            return res.status(500).json({
                ok:false,
                mensaje:"No se pudo actualizar el artículo"
            });
        }

        if(result.affectedRows === 0){

            return res.status(404).json({
                ok:false,
                mensaje:"Artículo no encontrado"
            });
        }

        res.json({
            ok:true
        });

    });

});

// 🔹 EDITAR PEDIDO
app.post('/update-order', protegerAdmin, (req, res) => {

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

    if (
        !idPedido ||
        !idArticulo ||
        !cantidadNumero ||
        cantidadNumero <= 0
    ) {

        return res.status(400).json({
            ok: false,
            mensaje: "Datos inválidos"
        });

    }

    // Buscar el artículo seleccionado
    conexion.query(`
        SELECT
            id_articulo,
            nombre,
            tasa,
            descripcion
        FROM articulos
        WHERE id_articulo = ?
        LIMIT 1
    `, [idArticulo], (err, resultados) => {

        if (err) {

            console.log(
                "❌ Error buscando artículo:",
                err
            );

            return res.status(500).json({
                ok: false,
                mensaje: "Error al buscar el artículo"
            });

        }

        if (resultados.length === 0) {

            return res.status(404).json({
                ok: false,
                mensaje: "Artículo no encontrado"
            });

        }

        const articulo =
            resultados[0];

        const precioUnidad =
            Number(articulo.tasa) || 0;

        const totalPrecio =
            cantidadNumero * precioUnidad;

        // Actualizar el pedido
        conexion.query(`
            UPDATE pedidos
            SET
                id_articulo = ?,
                articulo = ?,
                descripcion = ?,
                cantidad = ?,
                precio_unidad = ?,
                total_precio = ?
            WHERE id_pedido = ?
        `, [
            articulo.id_articulo,
            articulo.nombre,
            articulo.descripcion || null,
            cantidadNumero,
            precioUnidad,
            totalPrecio,
            idPedido
        ], (err, resultado) => {

            if (err) {

                console.log(
                    "❌ Error actualizando pedido:",
                    err
                );

                return res.status(500).json({
                    ok: false,
                    mensaje: "Error al actualizar el pedido"
                });

            }

            if (resultado.affectedRows === 0) {

                return res.status(404).json({
                    ok: false,
                    mensaje: "Pedido no encontrado"
                });

            }

            res.json({
                ok: true,
                mensaje: "Pedido actualizado correctamente"
            });

        });

    });

});
// 🔹 OBTENER USUARIO
app.get('/user/:id', (req, res) => {

    // 🔐 Debe existir una sesión iniciada
    if (!req.session.usuario) {
        return res.redirect('/login.html');
    }

    const rol = req.session.usuario.tipo_usuario;

    let id;

    // 🔐 El cliente solo puede consultar sus propios datos
    if (rol === 'cliente') {

        id = req.session.usuario.id_usuario;

    }
    // 🔐 Admin y superadmin pueden consultar al cliente solicitado
    else if (
        rol === 'admin' ||
        rol === 'superadmin'
    ) {

        id = req.params.id;

    }
    else {

        return res
            .status(403)
            .send('Acceso no autorizado ❌');

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
// 🔹 ACTUALIZAR PERFIL DEL CLIENTE
// ========================================

app.post(
    '/update-profile',
    protegerCliente,
    async (req, res) => {

        try {

            const idUsuario =
                req.session.usuario.id_usuario;

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


            // ========================================
            // 🔐 NORMALIZAR DATOS
            // ========================================

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


            // ========================================
            // 🔐 CAMPOS OBLIGATORIOS
            // ========================================

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
                    'Complete todos los datos del perfil.'
                );

            }


            // ========================================
            // 🔐 VALIDAR TELÉFONO
            // ========================================

            const telefonoValido =
                /^[0-9+\-\s()]{8,20}$/.test(
                    telefonoNormalizado
                );

            if (!telefonoValido) {

                return res.status(400).send(
                    'Ingrese un número de teléfono válido.'
                );

            }


            // ========================================
            // 🔐 VALIDAR CORREO
            // ========================================

            const correoValido =
                /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
                    correoNormalizado
                );

            if (!correoValido) {

                return res.status(400).send(
                    'Ingrese un correo electrónico válido.'
                );

            }


            // ========================================
            // 🔐 VALIDAR PROVINCIA
            // ========================================

            const provinciasValidas = [
                'San José',
                'Alajuela',
                'Cartago',
                'Heredia',
                'Guanacaste',
                'Puntarenas',
                'Limón'
            ];

            if (
                !provinciasValidas.includes(
                    provinciaNormalizada
                )
            ) {

                return res.status(400).send(
                    'Seleccione una provincia válida.'
                );

            }


            // ========================================
            // 🔹 BUSCAR USUARIO ACTUAL
            // ========================================

            conexion.query(
                `
                SELECT
                    correo,
                    password
                FROM usuarios
                WHERE id_usuario = ?
                LIMIT 1
                `,
                [idUsuario],
                async (errorUsuario, resultados) => {

                    if (
                        errorUsuario ||
                        resultados.length === 0
                    ) {

                        console.log(
                            '❌ Error buscando usuario:',
                            errorUsuario
                        );

                        return res.status(500).send(
                            'No se pudo actualizar el perfil.'
                        );

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
                        correoNormalizado !==
                        correoActual;

                    const quiereCambiarPassword =
                        Boolean(
                            passwordActual ||
                            passwordNueva ||
                            passwordConfirmar
                        );


                    // ========================================
                    // 🔐 SI CAMBIA CORREO,
                    // DEBE CAMBIAR CONTRASEÑA
                    // ========================================

                    if (
                        cambioCorreo &&
                        (
                            !passwordActual ||
                            !passwordNueva ||
                            !passwordConfirmar
                        )
                    ) {

                        return res.status(400).send(
                            'Para cambiar el correo debe ingresar su contraseña actual y establecer una nueva contraseña.'
                        );

                    }


                    // ========================================
                    // 🔐 VALIDAR CAMBIO DE CONTRASEÑA
                    // ========================================

                    if (quiereCambiarPassword) {

                        if (
                            !passwordActual ||
                            !passwordNueva ||
                            !passwordConfirmar
                        ) {

                            return res.status(400).send(
                                'Complete los tres campos de contraseña.'
                            );

                        }


                        const coincide =
                            await bcrypt.compare(
                                passwordActual,
                                usuarioActual.password
                            );

                        if (!coincide) {

                            return res.status(400).send(
                                'La contraseña actual no es correcta.'
                            );

                        }


                        if (
                            passwordNueva !==
                            passwordConfirmar
                        ) {

                            return res.status(400).send(
                                'Las nuevas contraseñas no coinciden.'
                            );

                        }


                        const passwordValido =
                            /^(?=.*[A-Za-z])(?=.*\d).{8,}$/
                                .test(passwordNueva);

                        if (!passwordValido) {

                            return res.status(400).send(
                                'La nueva contraseña debe tener mínimo 8 caracteres, al menos una letra y un número.'
                            );

                        }

                    }


                    // ========================================
                    // 🔐 COMPROBAR CORREO REPETIDO
                    // ========================================

                    conexion.query(
                        `
                        SELECT id_usuario
                        FROM usuarios
                        WHERE LOWER(TRIM(correo)) = ?
                        AND id_usuario <> ?
                        LIMIT 1
                        `,
                        [
                            correoNormalizado,
                            idUsuario
                        ],
                        async (
                            errorCorreo,
                            resultadosCorreo
                        ) => {

                            if (errorCorreo) {

                                console.log(
                                    '❌ Error verificando correo:',
                                    errorCorreo
                                );

                                return res.status(500).send(
                                    'No se pudo actualizar el perfil.'
                                );

                            }


                            if (
                                resultadosCorreo.length > 0
                            ) {

                                return res.status(409).send(
                                    'Este correo ya está registrado por otra cuenta.'
                                );

                            }


                            let passwordFinal =
                                usuarioActual.password;


                            if (quiereCambiarPassword) {

                                passwordFinal =
                                    await bcrypt.hash(
                                        passwordNueva,
                                        10
                                    );

                            }

                            // ========================================
                            // 🔹 ACTUALIZAR MISMO USUARIO
                            // ========================================

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
                                `,
                                [
                                    nombreNormalizado,
                                    apellidoNormalizado,
                                    telefonoNormalizado,
                                    correoNormalizado,
                                    passwordFinal,
                                    provinciaNormalizada,
                                    cantonNormalizado,
                                    distritoNormalizado,
                                    direccionNormalizada,
                                    idUsuario
                                ],
                                (errorActualizar) => {

                                    if (
                                        errorActualizar
                                    ) {

                                        console.log(
                                            '❌ Error actualizando perfil:',
                                            errorActualizar
                                        );

                                        return res
                                            .status(500)
                                            .send(
                                                'No se pudo actualizar el perfil.'
                                            );

                                    }


                                    // ========================================
                                    // 🔐 SI CAMBIÓ CORREO O CONTRASEÑA,
                                    // CERRAR LA SESIÓN
                                    // ========================================

                                    if (
                                        cambioCorreo ||
                                        quiereCambiarPassword
                                    ) {

                                        const mensajeSesion =
                                            cambioCorreo
                                                ? 'Perfil actualizado. Inicie sesión con su nuevo correo y contraseña.'
                                                : 'Contraseña actualizada correctamente. Inicie sesión nuevamente.';

                                        return req.session
                                            .destroy(() => {

                                                res.clearCookie(
                                                    'connect.sid'
                                                );

                                                return res.json({
                                                    ok: true,
                                                    cerrarSesion: true,
                                                    mensaje:
                                                        mensajeSesion
                                                });

                                            });

                                    }


                                    return res.json({
                                        ok: true,
                                        cerrarSesion: false,
                                        mensaje:
                                            'Perfil actualizado correctamente.'
                                    });

                                }
                            );

                        }
                    );

                }
            );

        } catch (error) {

            console.log(
                '❌ Error actualizando perfil:',
                error
            );

            return res.status(500).send(
                'No se pudo actualizar el perfil.'
            );

        }

    }
);


// 🔥 CREAR PEDIDO
app.post('/create-order', protegerAdmin, (req, res) => {

    const {
        id_usuario,
        id_articulo,
        articulo,
        descripcion,
        cantidad,
        precio_unidad,
        estado
    } = req.body;

    const peso_gramos = 0;

    const subtotal =
        Number(cantidad) *
        Number(precio_unidad);

    const total =
        subtotal;

    const estadosInicialesValidos = [
        'En_EEUU',
        'COLOMBIA'
    ];

    const estadoInicial =
        estadosInicialesValidos.includes(estado)
            ? estado
            : 'En_EEUU';

    conexion.query(`
        INSERT INTO pedidos
        (
            id_usuario,
            id_articulo,
            articulo,
            descripcion,
            cantidad,
            precio_unidad,
            peso_gramos,
            total_precio,
            estado
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
        id_usuario,
        id_articulo || null,
        articulo,
        descripcion || null,
        cantidad,
        precio_unidad,
        peso_gramos,
        total,
        estadoInicial
    ], (err) => {

        if (err) {

            console.log(
                "❌ ERROR SQL:",
                err
            );

            return res.status(500)
                .send("Error ❌");

        }

        res.json({
            ok: true
        });

    });

});

// 🔹 CALCULAR ENVÍO
app.post('/calcular-envio', (req, res) => {
    const { peso_gramos } = req.body;
    const peso = Number(peso_gramos) || 0;
    const envio = (peso / 1000) * 6000;

    res.json({ ok: true, envio });
});

// ======================================================
// 🔹 VER PEDIDOS ACTIVOS ADMIN
// ======================================================

app.get('/orders', protegerAdmin, (req, res) => {

    conexion.query(`
        SELECT
            p.*,
            u.nombre,
            u.apellido,
            IFNULL(SUM(a.monto_abono), 0) AS total_abonado,
            MAX(a.metodo_pago) AS metodo_pago,
            MAX(a.fecha_abono) AS fecha_abono,
            (p.total_precio - IFNULL(SUM(a.monto_abono), 0)) AS deuda

        FROM pedidos p

        JOIN usuarios u
            ON p.id_usuario = u.id_usuario

        LEFT JOIN abonos a
            ON p.id_pedido = a.id_pedido

        WHERE p.archivado = 0

        GROUP BY p.id_pedido

    `, (err, results) => {

        if (err) {

            console.log(
                "❌ Error cargando pedidos activos:",
                err
            );

            return res.json([]);
        }

        res.json(results);

    });

});

// ======================================================
// 🔹 VER PEDIDOS ARCHIVADOS
// ======================================================

app.get('/archived-orders', protegerAdmin, (req, res) => {

    conexion.query(`
        SELECT
            p.*,
            u.nombre,
            u.apellido,
            IFNULL(SUM(a.monto_abono), 0) AS total_abonado,
            MAX(a.metodo_pago) AS metodo_pago,
            MAX(a.fecha_abono) AS fecha_abono,
            (p.total_precio - IFNULL(SUM(a.monto_abono), 0)) AS deuda

        FROM pedidos p

        JOIN usuarios u
            ON p.id_usuario = u.id_usuario

        LEFT JOIN abonos a
            ON p.id_pedido = a.id_pedido

        WHERE p.archivado = 1

        GROUP BY p.id_pedido

        ORDER BY p.fecha_archivado DESC

    `, (err, results) => {

        if (err) {

            console.log(
                "❌ Error cargando pedidos archivados:",
                err
            );

            return res.status(500).json([]);
        }

        res.json(results);

    });

});

// ======================================================
// 🔹 ARCHIVAR PEDIDOS ACTIVOS DE UN CLIENTE
// ======================================================

app.post('/archive-client-orders', protegerAdmin, (req, res) => {

    const idUsuario = Number(req.body.id_usuario);

    if (!idUsuario) {

        return res.status(400).json({
            ok: false,
            mensaje: "Cliente inválido"
        });

    }

    conexion.query(`
        UPDATE pedidos
        SET
            archivado = 1,
            fecha_archivado = NOW()
        WHERE id_usuario = ?
        AND archivado = 0
    `, [idUsuario], (err, resultado) => {

        if (err) {

            console.log(
                "❌ Error archivando pedidos:",
                err
            );

            return res.status(500).json({
                ok: false,
                mensaje: "No se pudieron archivar los pedidos"
            });

        }

        if (resultado.affectedRows === 0) {

            return res.status(404).json({
                ok: false,
                mensaje: "No hay pedidos activos para archivar"
            });

        }

        return res.json({
            ok: true,
            mensaje: "Pedidos archivados correctamente"
        });

    });

});

// 🔹 CLIENTE VE SUS PEDIDOS
app.get('/client-orders/:id', protegerCliente, (req, res) => {

    const id = req.session.usuario.id_usuario;

    conexion.query(`
        SELECT p.*, 
        IFNULL(SUM(a.monto_abono), 0) AS total_abonado
        FROM pedidos p
        LEFT JOIN abonos a ON p.id_pedido = a.id_pedido
        WHERE p.id_usuario = ?
        GROUP BY p.id_pedido
    `, [id], (err, results) => {

        if (err) return res.json([]);

        res.json(results);
    });
});

// ======================================================
// 🔹 ABONOS
// ======================================================

app.post('/add-payment', protegerAdmin, (req, res) => {

    const idPedido =
        Number(req.body.id_pedido);

    const montoAbono =
        Number(req.body.monto_abono);

    const metodoPago =
        String(
            req.body.metodo_pago || ''
        ).trim();


    if (
        !idPedido ||
        !Number.isFinite(montoAbono) ||
        montoAbono <= 0 ||
        !metodoPago
    ) {

        return res.status(400).json({
            ok: false,
            mensaje: "Datos de abono inválidos."
        });

    }


    conexion.beginTransaction((errorTransaccion) => {

        if (errorTransaccion) {

            console.log(
                "❌ Error iniciando transacción de abono:",
                errorTransaccion
            );

            return res.status(500).json({
                ok: false,
                mensaje: "No se pudo iniciar el abono."
            });

        }


        /* =================================================
           BUSCAR PEDIDO Y BLOQUEARLO
        ================================================= */

        conexion.query(`
            SELECT
                id_pedido,
                peso_gramos,
                archivado
            FROM pedidos
            WHERE id_pedido = ?
            LIMIT 1
            FOR UPDATE
        `, [idPedido], (errorPedido, pedidos) => {

            if (errorPedido) {

                return conexion.rollback(() => {

                    console.log(
                        "❌ Error buscando pedido:",
                        errorPedido
                    );

                    return res.status(500).json({
                        ok: false,
                        mensaje: "No se pudo verificar el pedido."
                    });

                });

            }


            if (pedidos.length === 0) {

                return conexion.rollback(() => {

                    return res.status(404).json({
                        ok: false,
                        mensaje: "Pedido no encontrado."
                    });

                });

            }


            const pedido =
                pedidos[0];


            if (Number(pedido.archivado) === 1) {

                return conexion.rollback(() => {

                    return res.status(400).json({
                        ok: false,
                        mensaje: "No se pueden agregar abonos a un pedido archivado."
                    });

                });

            }


            /* =================================================
               CALCULAR ENVÍO DEL ARTÍCULO
            ================================================= */

            const peso =
                Number(
                    pedido.peso_gramos
                ) || 0;

            const envio =
                (peso / 1000) * 6000;


            /* =================================================
               OBTENER ABONOS EXISTENTES
            ================================================= */

            conexion.query(`
                SELECT
                    IFNULL(
                        SUM(monto_abono),
                        0
                    ) AS total_abonado
                FROM abonos
                WHERE id_pedido = ?
            `, [idPedido], (errorAbonos, resultadosAbonos) => {

                if (errorAbonos) {

                    return conexion.rollback(() => {

                        console.log(
                            "❌ Error consultando abonos:",
                            errorAbonos
                        );

                        return res.status(500).json({
                            ok: false,
                            mensaje: "No se pudo verificar el saldo."
                        });

                    });

                }


                const totalAbonado =
                    Number(
                        resultadosAbonos[0].total_abonado
                    ) || 0;


                const saldoPendiente =
                    envio - totalAbonado;


                /* =================================================
                   ARTÍCULO YA PAGADO
                ================================================= */

                if (saldoPendiente <= 0) {

                    return conexion.rollback(() => {

                        return res.status(400).json({
                            ok: false,
                            mensaje: "Este artículo ya está completamente pagado."
                        });

                    });

                }


                /* =================================================
                   NO PERMITIR ABONO MAYOR AL SALDO
                ================================================= */

                if (montoAbono > saldoPendiente) {

                    return conexion.rollback(() => {

                        return res.status(400).json({
                            ok: false,
                            mensaje:
                                `El saldo pendiente de este artículo es ₡${saldoPendiente.toLocaleString('es-CR')}. No puede ingresar un abono mayor.`
                        });

                    });

                }


                /* =================================================
                   GUARDAR ABONO
                ================================================= */

                const fecha =
                    new Date()
                        .toISOString()
                        .slice(0, 10);


                conexion.query(`
                    INSERT INTO abonos
                    (
                        id_pedido,
                        monto_abono,
                        fecha_abono,
                        metodo_pago
                    )
                    VALUES (?, ?, ?, ?)
                `, [
                    idPedido,
                    montoAbono,
                    fecha,
                    metodoPago
                ], (errorInsertar) => {

                    if (errorInsertar) {

                        return conexion.rollback(() => {

                            console.log(
                                "❌ Error guardando abono:",
                                errorInsertar
                            );

                            return res.status(500).json({
                                ok: false,
                                mensaje: "No se pudo guardar el abono."
                            });

                        });

                    }


                    conexion.commit((errorCommit) => {

                        if (errorCommit) {

                            return conexion.rollback(() => {

                                console.log(
                                    "❌ Error confirmando abono:",
                                    errorCommit
                                );

                                return res.status(500).json({
                                    ok: false,
                                    mensaje: "No se pudo completar el abono."
                                });

                            });

                        }


                        return res.json({
                            ok: true,
                            mensaje: "Abono guardado correctamente."
                        });

                    });

                });

            });

        });

    });

});


// 🔥 ACTUALIZAR PESO
app.post('/update-weight',protegerAdmin,  (req, res) => {
    const { id_pedido, peso_gramos } = req.body;

    const peso = Number(peso_gramos) || 0;
    const envio = (peso / 1000) * 6000;

    conexion.query(`
        SELECT cantidad, precio_unidad 
        FROM pedidos 
        WHERE id_pedido = ?
    `, [id_pedido], (err, results) => {

        if (err || results.length === 0) {
            return res.send("Error ❌");
        }

        const pedido = results[0];
        const subtotal = pedido.cantidad * pedido.precio_unidad;
        const total = subtotal + envio;

        conexion.query(`
            UPDATE pedidos 
            SET peso_gramos = ?, total_precio = ?
            WHERE id_pedido = ?
        `, [peso, total, id_pedido], (err) => {

            if (err) return res.send("Error ❌");

            res.json({ ok: true });
        });
    });
});


// 🔹 CAMBIAR ESTADO
app.post('/update-status',protegerAdmin,  (req, res) => {
    const { id_pedido, estado } = req.body;

    conexion.query(`
        UPDATE pedidos SET estado = ? WHERE id_pedido = ?
    `, [estado, id_pedido], (err) => {
        if (err) return res.send("Error ❌");
        res.json({ ok: true });
    });
});

// ======================================================
// 🔹 ELIMINAR UN PEDIDO ACTIVO
// ======================================================

app.post('/delete-order', protegerAdmin, (req, res) => {

    const idPedido = Number(req.body.id_pedido);

    if (!idPedido) {
        return res.status(400).json({
            ok: false,
            mensaje: "Pedido inválido"
        });
    }

    conexion.beginTransaction((errorTransaccion) => {

        if (errorTransaccion) {
            console.log(
                "❌ Error iniciando eliminación:",
                errorTransaccion
            );

            return res.status(500).json({
                ok: false,
                mensaje: "No se pudo iniciar la eliminación"
            });
        }

        conexion.query(`
            DELETE FROM abonos
            WHERE id_pedido = ?
        `, [idPedido], (errorAbonos) => {

            if (errorAbonos) {

                return conexion.rollback(() => {

                    console.log(
                        "❌ Error eliminando abonos:",
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
                            "❌ Error eliminando pedido:",
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
                                "❌ Error confirmando eliminación:",
                                errorCommit
                            );

                            return res.status(500).json({
                                ok: false,
                                mensaje: "No se pudo completar la eliminación"
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
// 🔹 ELIMINAR PEDIDOS ARCHIVADOS DE UN CLIENTE
// ======================================================

app.post('/delete-archived-client-orders', protegerAdmin, (req, res) => {

    const idUsuario = Number(req.body.id_usuario);

    if (!idUsuario) {
        return res.status(400).json({
            ok: false,
            mensaje: "Cliente inválido"
        });
    }

    conexion.beginTransaction((errorTransaccion) => {

        if (errorTransaccion) {
            console.log(
                "❌ Error iniciando transacción:",
                errorTransaccion
            );

            return res.status(500).json({
                ok: false,
                mensaje: "No se pudo iniciar la eliminación"
            });
        }

        conexion.query(`
            SELECT id_pedido
            FROM pedidos
            WHERE id_usuario = ?
            AND archivado = 1
        `, [idUsuario], (errorBuscar, pedidos) => {

            if (errorBuscar) {

                return conexion.rollback(() => {

                    console.log(
                        "❌ Error buscando pedidos archivados:",
                        errorBuscar
                    );

                    return res.status(500).json({
                        ok: false,
                        mensaje: "No se pudieron buscar los pedidos archivados"
                    });

                });
            }

            if (pedidos.length === 0) {

                return conexion.rollback(() => {

                    return res.status(404).json({
                        ok: false,
                        mensaje: "No hay pedidos archivados para eliminar"
                    });

                });
            }

            const idsPedidos =
                pedidos.map(
                    pedido => pedido.id_pedido
                );

            conexion.query(`
                DELETE FROM abonos
                WHERE id_pedido IN (?)
            `, [idsPedidos], (errorAbonos) => {

                if (errorAbonos) {

                    return conexion.rollback(() => {

                        console.log(
                            "❌ Error eliminando abonos:",
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
                    WHERE id_usuario = ?
                    AND archivado = 1
                `, [idUsuario], (errorPedidos, resultado) => {

                    if (errorPedidos) {

                        return conexion.rollback(() => {

                            console.log(
                                "❌ Error eliminando pedidos archivados:",
                                errorPedidos
                            );

                            return res.status(500).json({
                                ok: false,
                                mensaje: "No se pudieron eliminar los pedidos archivados"
                            });

                        });
                    }

                    conexion.commit((errorCommit) => {

                        if (errorCommit) {

                            return conexion.rollback(() => {

                                console.log(
                                    "❌ Error confirmando eliminación:",
                                    errorCommit
                                );

                                return res.status(500).json({
                                    ok: false,
                                    mensaje: "No se pudo completar la eliminación"
                                });

                            });
                        }

                        return res.json({
                            ok: true,
                            eliminados: resultado.affectedRows,
                            mensaje: "Pedidos archivados eliminados correctamente"
                        });

                    });

                });

            });

        });

    });

});

// 🔐 LÍMITE DE SOLICITUDES PARA RECUPERAR CONTRASEÑA
const forgotPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 3, // máximo 3 solicitudes
    standardHeaders: true,
    legacyHeaders: false,
    message: "Demasiadas solicitudes de recuperación. Intente nuevamente en 15 minutos."
});


// 🔹 OLVIDÉ CONTRASEÑA
app.post('/forgot-password', forgotPasswordLimiter, (req, res) => {

    console.log("📩 Entró una solicitud de recuperación");

    const correo = String(req.body.correo || '')
        .trim()
        .toLowerCase();

    const mensajeGenerico =
        "Si el correo está registrado, recibirás un enlace para recuperar tu contraseña.";

    if (!correo) {
        return res
            .status(400)
            .send("Ingrese un correo electrónico");
    }

    // 🔹 COMPROBAR SI EL USUARIO EXISTE
    conexion.query(
        `SELECT id_usuario FROM usuarios WHERE correo = ? LIMIT 1`,
        [correo],
        (err, resultados) => {

            if (err) {
                console.log("❌ Error buscando usuario:", err);

                return res
                    .status(500)
                    .send("Error del servidor");
            }

            // 🔐 NO REVELAR SI EL CORREO EXISTE O NO
            if (resultados.length === 0) {

                console.log(
                    "ℹ️ Solicitud recibida para un correo no registrado"
                );

                return res
                    .status(200)
                    .send(mensajeGenerico);
            }

            console.log("✅ Solicitud de recuperación válida");

            // 🔹 GENERAR TOKEN
            const token =
                crypto.randomBytes(32).toString('hex');

            // 🔹 15 MINUTOS
            const expiracion =
                Date.now() + (15 * 60 * 1000);

            // 🔹 GUARDAR TOKEN
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
                            "❌ Error guardando token:",
                            errorToken
                        );

                        return res
                            .status(500)
                            .send("Error del servidor");
                    }

                    console.log(
                        "✅ Token guardado correctamente"
                    );

                    // 🔹 LINK DE RECUPERACIÓN
                    /*const link =
                        `http://localhost:3000/reset-password/${token}`;
                    */

                    const BASE_URL = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

                    const link = `${BASE_URL}/reset-password/${token}`;

                    console.log(
                        "📤 Intentando enviar correo..."
                    );

                    try {

                        const info =
                            await transporter.sendMail({

                                from:
                                    'Tienda Ana <tiendaanacompras@gmail.com>',

                                to:
                                    correo,

                                subject:
                                    'Recuperar contraseña - Tienda Ana',

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
                                            Recibimos una solicitud para cambiar tu contraseña.
                                        </p>

                                        <p>
                                            Presiona el siguiente botón para crear una nueva contraseña:
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
                                                Cambiar contraseña
                                            </a>

                                        </div>

                                        <p>
                                            Este enlace tiene una duración de 15 minutos.
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

                        console.log(
                            "✅ CORREO DE RECUPERACIÓN ENVIADO:",
                            info.messageId
                        );

                        return res
                            .status(200)
                            .send(mensajeGenerico);

                    } catch (errorCorreo) {

                        console.log(
                            "❌ ERROR ENVIANDO RECUPERACIÓN:"
                        );

                        console.log(errorCorreo);

                        // 🔐 NO REVELAR INFORMACIÓN AL USUARIO
                        return res
                            .status(200)
                            .send(mensajeGenerico);
                    }
                }
            );
        }
    );
});

// 🔥 RESET PASSWORD (BONITO)
// ======================================================
// 🔥 PÁGINA PARA CAMBIAR CONTRASEÑA
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

        <title>Cambiar contraseña - Tienda Ana</title>

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
               🔐 REQUISITOS DE CONTRASEÑA
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
                    Tienda Ana Compras 🛍️
                </h1>

                <img
                    src="/logo.jpg"
                    alt="Logo Tienda Ana"
                    class="logo"
                >

            </div>


            <div class="tarjeta">


                ${mensajeHTML}


                <div class="icono">
                    🔐
                </div>


                <h2>
                    Nueva contraseña
                </h2>


                <p class="descripcion">

                    Cree una nueva contraseña
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
                        placeholder="Nueva contraseña"
                        autocomplete="new-password"
                        minlength="8"
                        required
                    >


                    <div
                        id="passwordRequisitos"
                        class="password-requisitos"
                    >
                        ⚠️ La contraseña debe tener mínimo
                        8 caracteres, al menos una letra
                        y un número.
                    </div>


                    <input
                        type="password"
                        name="confirm"
                        placeholder="Confirmar contraseña"
                        autocomplete="new-password"
                        required
                    >


                    <button type="submit">

                        Confirmar contraseña

                    </button>


                </form>


                <a
                    href="/login.html"
                    class="volver"
                >
                    Volver al inicio
                </a>


                <div class="seguridad">

                    🔒 Por seguridad,
                    el enlace de recuperación
                    tiene una duración limitada.

                </div>


            </div>


        </div>


        <script>

            // ========================================
            // 🔐 VALIDAR CONTRASEÑA MIENTRAS ESCRIBE
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


                    // Si está vacío, ocultar mensaje

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
            // 🔐 IMPEDIR ENVÍO SI NO CUMPLE
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

                    }

                }
            );

        </script>


    </body>

    </html>
    `;
}


// ======================================================
// ======================================================
// 🔥 MOSTRAR CAMBIO DE CONTRASEÑA
// ======================================================

app.get('/reset-password/:token', (req, res) => {

    const token =
        String(req.params.token || '').trim();


    // ============================================
    // 🔐 VALIDAR FORMATO DEL TOKEN
    // ============================================

    const tokenValido =
        /^[a-f0-9]{64}$/.test(token);

    if (!tokenValido) {

        console.log(
            "⚠️ Intento de recuperación con token inválido"
        );

        return res.send(
            paginaNuevaPassword(
                "",
                `
                ⚠️ Este enlace es inválido
                o está dañado.
                Solicite una nueva recuperación
                de contraseña.

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
    // 🔹 COMPROBAR TOKEN EN LA BASE DE DATOS
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
                "❌ Error comprobando token:",
                err
            );

            return res.send(
                paginaNuevaPassword(
                    "",
                    `
                    ❌ No fue posible verificar
                    el enlace de recuperación.
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
                    ⚠️ Este enlace es inválido
                    o ya expiró.
                    Solicite una nueva recuperación
                    de contraseña.

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
// 🔥 GUARDAR NUEVA CONTRASEÑA
// ======================================================

app.post('/reset-password/:token', (req, res) => {

    const token =
        String(req.params.token || '').trim();


    // ============================================
    // 🔐 VALIDAR FORMATO DEL TOKEN
    // ============================================

    const tokenValido =
        /^[a-f0-9]{64}$/.test(token);

    if (!tokenValido) {

        console.log(
            "⚠️ Intento de cambio con token inválido"
        );

        return res.send(
            paginaNuevaPassword(
                "",
                `
                ⚠️ Este enlace de recuperación
                es inválido o está dañado.

                <br><br>

                Solicite una nueva recuperación
                de contraseña.

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
    // 🔹 VALIDAR CAMPOS
    // ============================================

    if (!password || !confirm) {

        return res.send(
            paginaNuevaPassword(
                token,
                `
                ⚠️ Complete ambos campos
                para continuar.
                `,
                "error"
            )
        );
    }



    // ============================================
    // 🔐 VALIDAR SEGURIDAD DE LA CONTRASEÑA
    // ============================================

    const passwordValido =
        /^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(password);

    if (!passwordValido) {

        return res.send(
            paginaNuevaPassword(
                token,
                `
                ⚠️ La contraseña debe tener
                al menos 8 caracteres,
                una letra y un número.
                `,
                "error"
            )
        );
    }



    // ============================================
    // 🔹 VALIDAR QUE COINCIDAN
    // ============================================

    if (password !== confirm) {

        return res.send(
            paginaNuevaPassword(
                token,
                `
                ⚠️ Las contraseñas
                no coinciden.
                Inténtelo nuevamente.
                `,
                "error"
            )
        );
    }



    // ============================================
    // 🔹 COMPROBAR TOKEN ANTES DE CAMBIAR
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
    async (err, results) => {


        if (err) {

            console.log(
                "❌ Error comprobando token:",
                err
            );

            return res.send(
                paginaNuevaPassword(
                    token,
                    `
                    ❌ Ocurrió un error
                    al verificar la recuperación.
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
                    ⚠️ El enlace de recuperación
                    es inválido o ya expiró.

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



        try {


            // ============================================
            // 🔹 ENCRIPTAR NUEVA CONTRASEÑA
            // ============================================

            const hash =
                await bcrypt.hash(
                    password,
                    10
                );



            // ============================================
            // 🔹 GUARDAR NUEVA CONTRASEÑA
            // ============================================

            conexion.query(`
                UPDATE usuarios

                SET
                    password = ?,
                    reset_token = NULL,
                    reset_expiration = NULL

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
                        "❌ Error actualizando contraseña:",
                        errorActualizar
                    );

                    return res.send(
                        paginaNuevaPassword(
                            token,
                            `
                            ❌ No fue posible
                            actualizar la contraseña.
                            Inténtelo nuevamente.
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
                            ⚠️ No fue posible
                            actualizar la contraseña.
                            El enlace puede haber expirado.
                            `,
                            "error"
                        )
                    );
                }



                // ============================================
                // 🔹 MISMA PÁGINA + MENSAJE ARRIBA
                // ============================================

                return res.send(
                    paginaNuevaPassword(
                        "",
                        `
                        ✅ Su contraseña ha sido
                        actualizada correctamente.

                        <br><br>

                        Puede volver al
                        <a href="/login.html">
                            inicio
                        </a>
                        para iniciar sesión.
                        `,
                        "ok"
                    )
                );


            });


        } catch (errorHash) {


            console.log(
                "❌ Error preparando contraseña:",
                errorHash
            );


            return res.send(
                paginaNuevaPassword(
                    token,
                    `
                    ❌ No fue posible
                    actualizar la contraseña.
                    `,
                    "error"
                )
            );


        }


    });

});


// 🔥 SERVER
/*app.listen(3000, () => {
    console.log('🚀 http://localhost:3000');
});*/

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 http://localhost:${PORT}`);
});