require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Resend } = require('resend');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
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
// ======================================================
// 🔐 PROTEGER PÁGINAS DEL CLIENTE
// ======================================================

// 🔐 Página principal del cliente
app.get('/client.html', protegerCliente, (req, res) => {

    res.sendFile(
        path.join(__dirname, 'public', 'client.html')
    );

});


// 🔐 Página de archivos del cliente
app.get('/client_archived.html', protegerCliente, (req, res) => {

    res.sendFile(
        path.join(__dirname, 'public', 'client_archived.html')
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
        // 🔐 VALIDAR NOMBRE
        // SOLO LETRAS
        // ============================================

        const nombreValido =
            /^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s'-]+$/.test(
                nombreNormalizado
            );


        if (!nombreValido) {

            return res.status(400).send(
                "En el nombre solo se permiten letras."
            );

        }


        // ============================================
        // 🔐 VALIDAR APELLIDO
        // SOLO LETRAS
        // ============================================

        const apellidoValido =
            /^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s'-]+$/.test(
                apellidoNormalizado
            );


        if (!apellidoValido) {

            return res.status(400).send(
                "En el apellido solo se permiten letras."
            );

        }


        // ============================================
        // 🔐 VALIDAR LONGITUD NOMBRE Y APELLIDO
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
        // SOLO NÚMEROS
        // NO SE LIMITA A 8 DÍGITOS
        // ============================================

        const telefonoValido =
            /^\d+$/.test(
                telefonoNormalizado
            );


        if (!telefonoValido) {

            return res.status(400).send(
                "En el teléfono solo se permiten números."
            );

        }


        // Evitar números excesivamente largos

        if (telefonoNormalizado.length > 20) {

            return res.status(400).send(
                "El número de teléfono es demasiado largo."
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
            /^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(
                password
            );


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
            [
                correoNormalizado
            ],
            async (
                errorBuscar,
                resultados
            ) => {


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
        cantidad,
        peso_gramos
    } = req.body;

    const idPedido =
        Number(id_pedido);

    const idArticulo =
        Number(id_articulo);

    const cantidadNumero =
        Number(cantidad);

    const pesoNumero =
        Number(peso_gramos);


    if (
        !Number.isInteger(idPedido) ||
        idPedido <= 0 ||
        !Number.isInteger(idArticulo) ||
        idArticulo <= 0 ||
        !Number.isInteger(cantidadNumero) ||
        cantidadNumero <= 0 ||
        !Number.isFinite(pesoNumero) ||
        pesoNumero <= 0
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
        // El nuevo peso REEMPLAZA el peso anterior.
        conexion.query(`
            UPDATE pedidos
            SET
                id_articulo = ?,
                articulo = ?,
                descripcion = ?,
                cantidad = ?,
                precio_unidad = ?,
                total_precio = ?,
                peso_gramos = ?
            WHERE id_pedido = ?
        `, [
            articulo.id_articulo,
            articulo.nombre,
            articulo.descripcion || null,
            cantidadNumero,
            precioUnidad,
            totalPrecio,
            pesoNumero,
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
// 🔥 GRUPOS DE COMPRA / FACTURAS
// ========================================


/*
    🔹 CREAR NUEVA COMPRA

    Cada vez que Ana inicia una compra nueva
    en EEUU o Colombia, se crea un grupo nuevo.

    Ejemplo:
    grupo 1 = EEUU
    grupo 2 = Colombia
    grupo 3 = EEUU
/*
    🔹 OBTENER O CREAR FACTURA ACTIVA

    REGLA:

    Un cliente puede tener solamente UNA factura
    activa por país.

    Ejemplo:

    Justin + EEUU
    → todos los artículos nuevos de EEUU
      entran en la misma factura activa.

    Justin + COLOMBIA
    → todos los artículos nuevos de Colombia
      entran en la misma factura activa.

    Cuando una factura se archiva, deja de
    considerarse activa para ese cliente y país.
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
                    'Cliente inválido'
            });

        }


        /* =============================================
           VALIDAR PAÍS
        ============================================= */

        if(
            !paisesValidos.includes(
                paisOrigen
            )
        ){

            return res.status(400).json({
                ok: false,
                mensaje:
                    'País de origen inválido'
            });

        }


        /*
            =============================================
            BUSCAR FACTURA ACTIVA DEL CLIENTE + PAÍS

            Una factura se considera disponible si
            todavía tiene al menos un pedido NO
            archivado de ese cliente y ese país.
            =============================================
        */

        conexion.query(`
            SELECT
                p.grupo_compra

            FROM pedidos p

            INNER JOIN grupos_compra g
                ON g.id_grupo = p.grupo_compra

            WHERE p.id_usuario = ?
            AND p.pais_origen = ?
            AND p.archivado = 0
            AND p.grupo_compra IS NOT NULL
            AND g.activo = 1

            ORDER BY
                p.id_pedido DESC

            LIMIT 1
        `, [
            idUsuario,
            paisOrigen
        ], (errorBuscar, resultados) => {


            if(errorBuscar){

                console.log(
                    '❌ ERROR BUSCANDO FACTURA ACTIVA:',
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

                    pais_origen:
                        paisOrigen,

                    existente:
                        true
                });

            }


            /*
                =========================================
                NO EXISTE FACTURA ACTIVA

                Ahora sí creamos un grupo nuevo.
                =========================================
            */

            conexion.query(`
                INSERT INTO grupos_compra
                (
                    pais_origen,
                    activo
                )
                VALUES (?, 1)
            `, [
                paisOrigen
            ], (errorCrear, resultado) => {


                if(errorCrear){

                    console.log(
                        '❌ ERROR CREANDO GRUPO DE COMPRA:',
                        errorCrear
                    );


                    return res.status(500).json({
                        ok: false,
                        mensaje:
                            'No se pudo crear la factura'
                    });

                }


                return res.json({
                    ok: true,

                    grupo_compra:
                        resultado.insertId,

                    pais_origen:
                        paisOrigen,

                    existente:
                        false
                });

            });

        });

    }
);

// ======================================================
// 🔹 CREAR PEDIDO
// ======================================================

app.post('/create-order', protegerAdmin, (req, res) => {

    const {
        id_usuario,
        id_articulo,
        articulo,
        descripcion,
        cantidad,
        precio_unidad,
        estado,
        pais_origen,
        grupo_compra
    } = req.body;


    // ======================================================
    // 🔐 NORMALIZAR DATOS
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


    // ======================================================
    // 🔐 VALIDAR CLIENTE
    // ======================================================

    if(
        !Number.isInteger(idUsuario) ||
        idUsuario <= 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: 'Cliente inválido'
        });

    }


    // ======================================================
    // 🔐 VALIDAR ARTÍCULO
    // ======================================================

    if(
        !articuloLimpio
    ){

        return res.status(400).json({
            ok: false,
            mensaje: 'Artículo inválido'
        });

    }


    // ======================================================
    // 🔐 VALIDAR CANTIDAD
    // ======================================================

    if(
        !Number.isFinite(cantidadNumero) ||
        cantidadNumero <= 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: 'Cantidad inválida'
        });

    }


    // ======================================================
    // 🔐 VALIDAR PRECIO
    // ======================================================

    if(
        !Number.isFinite(precioUnidad) ||
        precioUnidad < 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: 'Precio inválido'
        });

    }


    // ======================================================
    // 🔐 VALIDAR GRUPO / FACTURA
    // ======================================================

    if(
        !Number.isInteger(grupoCompra) ||
        grupoCompra <= 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: 'Factura inválida'
        });

    }


    // ======================================================
    // 🔐 NORMALIZAR PAÍS
    // ======================================================

    let paisOrigen =
        String(
            pais_origen || ''
        )
        .trim()
        .toUpperCase();


    /*
        También aceptamos el valor antiguo
        que utiliza el botón del dashboard.
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
                'País de origen inválido'
        });

    }


    // ======================================================
    // 🔹 ESTADO INICIAL SEGÚN PAÍS
    // ======================================================

    const estadoInicial =
        paisOrigen === 'COLOMBIA'
            ? 'COLOMBIA'
            : 'En_EEUU';


    // ======================================================
    // 🔐 COMPROBAR QUE EL CLIENTE EXISTE
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
                '❌ Error verificando cliente:',
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
        // 🔐 COMPROBAR GRUPO / FACTURA
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
                    '❌ Error verificando factura:',
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
            // 🔐 FACTURA DEBE ESTAR ACTIVA
            // ==================================================

            if(
                Number(grupo.activo) !== 1
            ){

                return res.status(400).json({
                    ok: false,
                    mensaje:
                        'La factura ya no está activa'
                });

            }


            // ==================================================
            // 🔐 PAÍS DE FACTURA DEBE COINCIDIR
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
                        'El país de la factura no coincide con el pedido'
                });

            }


            /*
                ==================================================
                🔐 EVITAR MEZCLAR CLIENTES EN UNA FACTURA

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
                        '❌ Error verificando pedidos de la factura:',
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
                // 🔹 CALCULAR TOTAL DEL PRODUCTO
                // ==============================================

                const totalPrecio =
                    cantidadNumero *
                    precioUnidad;


                // ==============================================
                // 🔹 GUARDAR PEDIDO
                // ==============================================

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
                        estado,
                        pais_origen,
                        grupo_compra,
                        archivado
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, 0)
                `, [
                    idUsuario,
                    idArticulo,
                    articuloLimpio,
                    descripcionLimpia || null,
                    cantidadNumero,
                    precioUnidad,
                    totalPrecio,
                    estadoInicial,
                    paisOrigen,
                    grupoCompra
                ], (errorInsertar, resultado) => {


                    if(errorInsertar){

                        console.log(
                            '❌ Error creando pedido:',
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

        ORDER BY
            u.nombre ASC,
            u.apellido ASC,
            p.grupo_compra ASC,
            p.id_pedido ASC

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
// 🔹 ARCHIVAR PEDIDOS ACTIVOS DE UNA FACTURA DEL CLIENTE
// ======================================================

app.post('/archive-client-orders', protegerAdmin, (req, res) => {

    const idUsuario =
        Number(req.body.id_usuario);

    const grupoCompra =
        Number(req.body.grupo_compra);


    // ======================================================
    // 🔐 VALIDAR CLIENTE
    // ======================================================

    if(
        !Number.isInteger(idUsuario) ||
        idUsuario <= 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: "Cliente inválido"
        });

    }


    // ======================================================
    // 🔐 VALIDAR GRUPO / FACTURA
    // ======================================================

    if(
        !Number.isInteger(grupoCompra) ||
        grupoCompra <= 0
    ){

        return res.status(400).json({
            ok: false,
            mensaje: "Factura inválida"
        });

    }


    // ======================================================
    // 🔹 ARCHIVAR SOLO ESA FACTURA DEL CLIENTE
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
                "❌ Error archivando factura:",
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
// 🔹 CLIENTE VE SUS PEDIDOS ACTIVOS
// ======================================================

app.get('/client-orders/:id', protegerCliente, (req, res) => {

    // Por seguridad se usa el ID de la sesión,
    // no el ID enviado en la URL.
    const id =
        req.session.usuario.id_usuario;


    conexion.query(`
        SELECT
            p.*,
            IFNULL(
                SUM(a.monto_abono),
                0
            ) AS total_abonado
        FROM pedidos p
        LEFT JOIN abonos a
            ON p.id_pedido = a.id_pedido
        WHERE
            p.id_usuario = ?
            AND p.archivado = 0
        GROUP BY p.id_pedido
    `, [id], (err, results) => {

        if (err) {

            console.log(
                "❌ Error cargando pedidos del cliente:",
                err
            );

            return res.status(500).json([]);

        }


        res.json(results);

    });

});


// ======================================================
// 🔹 CLIENTE VE SUS PEDIDOS ARCHIVADOS
// ======================================================

app.get('/client-archived-orders/:id', protegerCliente, (req, res) => {

    // Igual que arriba: el cliente solamente puede
    // consultar los pedidos de su propia sesión.
    const id =
        req.session.usuario.id_usuario;


    conexion.query(`
        SELECT
            p.*,
            IFNULL(
                SUM(a.monto_abono),
                0
            ) AS total_abonado
        FROM pedidos p
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
                "❌ Error cargando archivos del cliente:",
                err
            );

            return res.status(500).json([]);

        }


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
// 🔹 ELIMINAR UNA FACTURA ARCHIVADA ESPECÍFICA
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
            mensaje: "Cliente inválido"
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
            mensaje: "Factura o pedido inválido"
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
                            "❌ Error buscando factura archivada:",
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
                            mensaje: "No se encontró la factura archivada seleccionada"
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
                                    "❌ Error eliminando abonos:",
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
                                            "❌ Error eliminando pedidos:",
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
                                    revisamos si el grupo quedó sin pedidos.
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
                                                        "❌ Error revisando grupo:",
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
                                                                    "❌ Error eliminando grupo:",
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
const { data, error } =
    await resend.emails.send({

        from:
            'Tienda Ana <onboarding@resend.dev>',

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

if (error) {
    throw error;
}

console.log(
    "✅ CORREO DE RECUPERACIÓN ENVIADO:",
    data.id
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