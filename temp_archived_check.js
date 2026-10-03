
// ========================================
// MENÚ MÓVIL
// ========================================

const botonMenuMovil =
    document.getElementById(
        "botonMenuMovil"
    );

const menuMovilOpciones =
    document.getElementById(
        "menuMovilOpciones"
    );

botonMenuMovil.addEventListener(
    "click",
    () => {

        const abierto =
            menuMovilOpciones.style.display ===
            "block";

        if(abierto){

            menuMovilOpciones.style.display =
                "none";

            botonMenuMovil.innerText =
                "☰";

            botonMenuMovil.setAttribute(
                "aria-label",
                "Abrir menú"
            );

        }else{

            menuMovilOpciones.style.display =
                "block";

            botonMenuMovil.innerText =
                "✕";

            botonMenuMovil.setAttribute(
                "aria-label",
                "Cerrar menú"
            );

        }

    }
);
// ======================================================
// 🔹 CERRAR MENÚ MÓVIL AL TOCAR FUERA
// ======================================================

document.addEventListener("click", (event) => {

    const menuAbierto =
        menuMovilOpciones.style.display === "block";

    if (!menuAbierto) {
        return;
    }

    // Si tocó dentro del menú o en ☰ / ✕,
    // no cerrarlo desde aquí
    if (
        menuMovilOpciones.contains(event.target) ||
        botonMenuMovil.contains(event.target)
    ) {
        return;
    }

    // Cerrar menú
    menuMovilOpciones.style.display =
        "none";

    // Restaurar ☰
    botonMenuMovil.innerText =
        "☰";

    botonMenuMovil.setAttribute(
        "aria-label",
        "Abrir menú"
    );

});

/* =========================================================
   VARIABLES
========================================================= */

let pedidosArchivados = [];

let archivadosPorCliente = {};

let clienteArchivadoSeleccionado = null;

let clienteArchivadoParaEliminar = null;

let grupoArchivadoParaEliminar = null;

let pedidoArchivadoParaEliminar = null;

let paginaActualArchivados = 1;
const clientesPorPaginaArchivados = 20;
let clienteParaDesarchivar = null;
let grupoParaDesarchivar = null;

/* =========================================================
   TRADUCIR ESTADOS
========================================================= */

function traducirEstado(estado){

    switch(estado){

        case "En_EEUU":
            return "Estados Unidos";

        case "EN_CAMINO":
            return "En camino";

        case "COSTA_RICA":
            return "Costa Rica";

        case "EMPACADO":
            return "Empacado";

        case "ENTREGADO":
            return "Entregado";

        default:
            return estado || "-";

    }

}


/* =========================================================
   FORMATEAR DINERO
========================================================= */

function moneda(valor){

    return "₡" +
        Number(valor || 0)
        .toLocaleString(
            "es-CR",
            {
                minimumFractionDigits: 0,
                maximumFractionDigits: 2
            }
        ).replace(/[\u00A0\u202F ]/g, ".");

}


/* =========================================================
   FORMATEAR FECHA
========================================================= */

function formatearFecha(fecha){

    if(!fecha){
        return "-";
    }

    return String(fecha).split("T")[0];

}


/* =========================================================
   CARGAR PEDIDOS ARCHIVADOS
========================================================= */

async function cargarArchivados(){

    try{

        const respuesta =
            await fetch(
                "/archived-orders"
            );


        if(!respuesta.ok){

            console.error(
                "Error cargando archivados"
            );

            return;

        }


        const data =
            await respuesta.json();


        pedidosArchivados =
            data;


        archivadosPorCliente =
            {};


        /* =================================================
           AGRUPAR POR CLIENTE Y FACTURA
        ================================================= */

        data.forEach(pedido => {

            const idUsuario =
                Number(
                    pedido.id_usuario
                );


            if(
                !archivadosPorCliente[
                    idUsuario
                ]
            ){

                archivadosPorCliente[
                    idUsuario
                ] = {

                    id_usuario:
                        idUsuario,

                    nombre:
                        pedido.nombre,

                    apellido:
                        pedido.apellido,

                    grupos:
                        {}

                };

            }


            const cliente =
                archivadosPorCliente[
                    idUsuario
                ];


            /* =============================================
               IDENTIFICAR FACTURA / GRUPO
            ============================================= */

            let claveGrupo;


            if(
                pedido.grupo_compra !== null &&
                pedido.grupo_compra !== undefined
            ){

                claveGrupo =
                    String(
                        Number(
                            pedido.grupo_compra
                        )
                    );

            }else{

                /*
                    Pedido antiguo sin grupo.
                    Se mantiene separado para no mezclarlo
                    con otros pedidos archivados.
                */

                claveGrupo =
                    `legacy-${pedido.id_pedido}`;

            }


            if(
                !cliente.grupos[
                    claveGrupo
                ]
            ){

                cliente.grupos[
                    claveGrupo
                ] = {

                    grupo_compra:
                        pedido.grupo_compra !== null &&
                        pedido.grupo_compra !== undefined
                            ? Number(
                                pedido.grupo_compra
                            )
                            : null,

                    numero_factura:
                        pedido.numero_factura !== null &&
                        pedido.numero_factura !== undefined
                            ? Number(
                                pedido.numero_factura
                            )
                            : null,

                    pais_origen:
                        pedido.pais_origen || null,

                    peso_total:
                        0,

                    envio_total:
                        0,

                    total_abonado:
                        0,

                    fecha_abono:
                        null,

                    fecha_archivado:
                        null,

                    estados:
                        new Set(),

                    pedidos:
                        []

                };

            }


            const grupo =
                cliente.grupos[
                    claveGrupo
                ];


            grupo.pedidos.push(
                pedido
            );


            /* =============================================
               PESO
            ============================================= */

            const peso =
                Number(
                    pedido.peso_gramos
                ) || 0;


            grupo.peso_total +=
                peso;


            /* =============================================
               VALOR ENVÍO
            ============================================= */

            const envio =
                (peso / 1000) *
                6000;


            grupo.envio_total +=
                envio;


            /* =============================================
               ABONO
            ============================================= */

            grupo.total_abonado +=
                Number(
                    pedido.total_abonado
                ) || 0;


            /* =============================================
               ESTADO
            ============================================= */

            if(pedido.estado){

                grupo.estados.add(
                    pedido.estado
                );

            }


            /* =============================================
               PAÍS DE ORIGEN
            ============================================= */

            if(
                !grupo.pais_origen &&
                pedido.pais_origen
            ){

                grupo.pais_origen =
                    pedido.pais_origen;

            }


            /* =============================================
               FECHA DEL ÚLTIMO ABONO
            ============================================= */

            if(pedido.fecha_abono){

                const fecha =
                    String(
                        pedido.fecha_abono
                    ).split("T")[0];


                if(
                    !grupo.fecha_abono ||
                    fecha >
                    grupo.fecha_abono
                ){

                    grupo.fecha_abono =
                        fecha;

                }

            }


            /* =============================================
               FECHA ARCHIVADO MÁS RECIENTE
            ============================================= */

            if(
                pedido.fecha_archivado
            ){

                const fechaArchivado =
                    String(
                        pedido.fecha_archivado
                    ).split("T")[0];


                if(
                    !grupo.fecha_archivado ||
                    fechaArchivado >
                    grupo.fecha_archivado
                ){

                    grupo.fecha_archivado =
                        fechaArchivado;

                }

            }

        });


        mostrarArchivados();


    }catch(error){

        console.error(
            "Error cargando pedidos archivados:",
            error
        );

    }

}

/* =========================================================
   MOSTRAR ARCHIVADOS
========================================================= */

function mostrarArchivados(){

    if(
        clienteArchivadoSeleccionado
    ){

        mostrarFacturasArchivadasCliente(
            clienteArchivadoSeleccionado
        );

        return;

    }


    mostrarListaClientesArchivados();

}
function obtenerClientesArchivadosFiltrados(){

    const buscar =
        document.getElementById(
            "buscar"
        );

    const valor =
        buscar
            ? buscar.value
                .toLowerCase()
                .trim()
            : "";


    return Object.values(
        archivadosPorCliente
    )
    .filter(
        cliente => {

            const nombreCompleto =
                `${cliente.nombre} ${cliente.apellido}`
                .toLowerCase();

            return nombreCompleto.includes(
                valor
            );

        }
    )
    .sort(
        (a, b) => {
            const facturasA = Object.values(a.grupos)
                .map(grupo => Number(grupo.numero_factura))
                .filter(numero => Number.isFinite(numero) && numero > 0);

            const facturasB = Object.values(b.grupos)
                .map(grupo => Number(grupo.numero_factura))
                .filter(numero => Number.isFinite(numero) && numero > 0);

            const facturaA = facturasA.length ? Math.min(...facturasA) : Number.MAX_SAFE_INTEGER;
            const facturaB = facturasB.length ? Math.min(...facturasB) : Number.MAX_SAFE_INTEGER;

            return facturaA - facturaB;
        }
    );

}
function actualizarPaginacionArchivados(){

    const clientes =
        obtenerClientesArchivadosFiltrados();

    const totalClientes =
        clientes.length;

    const totalPaginas =
        Math.ceil(
            totalClientes /
            clientesPorPaginaArchivados
        );


    if(
        totalPaginas > 0 &&
        paginaActualArchivados > totalPaginas
    ){
        paginaActualArchivados =
            totalPaginas;
    }


    const inicio =
        totalClientes === 0
            ? 0
            : (
                (paginaActualArchivados - 1) *
                clientesPorPaginaArchivados
              ) + 1;


    const fin =
        Math.min(
            paginaActualArchivados *
            clientesPorPaginaArchivados,
            totalClientes
        );


    const texto =
        document.getElementById(
            "textoPaginacionArchivados"
        );

    const anterior =
        document.getElementById(
            "btnAnteriorArchivados"
        );

    const siguiente =
        document.getElementById(
            "btnSiguienteArchivados"
        );


    if(texto){

        texto.textContent =
            `${inicio} - ${fin} de ${totalClientes}`;

    }


    if(anterior){

        anterior.style.display =
            paginaActualArchivados > 1
                ? "inline-block"
                : "none";

    }


    if(siguiente){

        siguiente.style.display =
            paginaActualArchivados < totalPaginas
                ? "inline-block"
                : "none";

    }

}


function paginaAnteriorArchivados(){

    if(paginaActualArchivados <= 1){
        return;
    }

    paginaActualArchivados--;

    mostrarListaClientesArchivados();

}
function paginaSiguienteArchivados(){

    const clientes =
        obtenerClientesArchivadosFiltrados();

    const totalClientes =
        clientes.length;

    const totalPaginas =
        Math.ceil(
            totalClientes /
            clientesPorPaginaArchivados
        );

    if(
        paginaActualArchivados >=
        totalPaginas
    ){
        return;
    }

    paginaActualArchivados++;

    mostrarListaClientesArchivados();

}
/* =========================================================
   MOSTRAR LISTA DE CLIENTES ARCHIVADOS
========================================================= */
function mostrarListaClientesArchivados(){

    const botonExpandir =
        document.getElementById(
            "btnExpandir"
        );

    if(botonExpandir){
        botonExpandir.textContent =
            "Expandir";
    }


    const tabla =
        document.getElementById(
            "tablaArchivados"
        );


    const encabezado =
        document.querySelector(
            "table thead"
        );


    encabezado.innerHTML = `

        <tr>

            <th>Cliente</th>

        </tr>

    `;


  const clientesFiltrados =
    obtenerClientesArchivadosFiltrados();


const inicio =
    (paginaActualArchivados - 1) *
    clientesPorPaginaArchivados;


const fin =
    inicio +
    clientesPorPaginaArchivados;


const clientes =
    clientesFiltrados.slice(
        inicio,
        fin
    );

    clientes.sort(
        (a, b) => {

            const nombreA =
                `${a.nombre} ${a.apellido}`
                .toLowerCase();


            const nombreB =
                `${b.nombre} ${b.apellido}`
                .toLowerCase();


            return nombreA.localeCompare(
                nombreB,
                "es"
            );

        }
    );


    let html = "";


    clientes.forEach(
        cliente => {

            const grupos =
                Object.values(cliente.grupos);

            const gruposConFactura =
                grupos
                .filter(
                    grupo =>
                        Number(grupo.numero_factura) > 0
                )
                .sort(
                    (a, b) =>
                        Number(a.numero_factura) -
                        Number(b.numero_factura)
                );

            const grupoPrincipal =
                gruposConFactura.length > 0
                    ? gruposConFactura[0]
                    : null;

            let numeroFactura = "-";
            let claseFactura = "";

            if(grupoPrincipal){

                numeroFactura =
                    grupoPrincipal.numero_factura;

                const saldo =
                    (Number(grupoPrincipal.envio_total) || 0) -
                    (Number(grupoPrincipal.total_abonado) || 0);

                claseFactura =
                    saldo > 0
                        ? "saldo-pendiente"
                        : "saldo-pagado";
            }

            html += `
                <tr
                    class="fila-cliente"
                    onclick="toggleClienteArchivado(
                        ${cliente.id_usuario}
                    )"
                    style="cursor:pointer;"
                >

                    <td
                        class="${claseFactura}"
                        style="
                            width:110px;
                            text-align:center;
                            font-weight:bold;
                            border-right:2px solid #d8d8d8;
                        "
                    >
                        ${numeroFactura}
                    </td>

                    <td
                        style="
                            text-align:left;
                            padding-left:45px;
                            font-weight:bold;
                            color:#a85c78;
                        "
                    >
                        <span
                            id="flecha-archivado-${cliente.id_usuario}"
                        >
                            ▶
                        </span>

                        ${cliente.nombre}
                        ${cliente.apellido}
                    </td>

                </tr>

                <tr
                    id="detalle-cliente-archivado-${cliente.id_usuario}"
                    style="display:none;"
                >

                    <td
                        colspan="2"
                        style="
                            padding:0;
                            background:#fdf6f0;
                        "
                    >
                        <div
                            id="contenido-cliente-archivado-${cliente.id_usuario}"
                        >
                        </div>
                    </td>

                </tr>
            `;

        }
    );

    tabla.innerHTML =
        html;

actualizarPaginacionArchivados();


/* Alinear exactamente la raya del encabezado con la raya de Factura */
requestAnimationFrame(() => {

    const celdaFactura =
        document.querySelector("#tablaArchivados tr td:first-child");

    const encabezadoFactura =
        document.querySelector(".barra-cliente-fija > div:first-child");

    if(celdaFactura && encabezadoFactura){

        const posicion =
            celdaFactura.getBoundingClientRect().right;

        encabezadoFactura.style.width =
            `${posicion}px`;

        encabezadoFactura.style.minWidth =
            `${posicion}px`;

        encabezadoFactura.style.maxWidth =
            `${posicion}px`;
    }

});

}
/* =========================================================
   ABRIR CLIENTE ARCHIVADO
========================================================= */

function toggleClienteArchivado(
    idUsuario
){

    const modal =
        document.getElementById(
            "modalDetalleArchivado"
        );

    const contenidoModal =
        document.getElementById(
            "contenidoModalDetalleArchivado"
        );

    if(
        !modal ||
        !contenidoModal
    ){
        return;
    }

    const clientes =
        obtenerClientesArchivadosFiltrados();

    const cliente =
        clientes.find(
            c =>
                Number(c.id_usuario) ===
                Number(idUsuario)
        );

    if(!cliente){
        return;
    }

    contenidoModal.innerHTML = "";

    modal.dataset.clienteId =
        String(idUsuario);

    modal.classList.add(
        "abierto"
    );

    mostrarFacturasArchivadasCliente(
        idUsuario,
        true
    );

}



/* =========================================================
   EXPANDIR / COLAPSAR TODOS LOS CLIENTES ARCHIVADOS
========================================================= */

function toggleTodosClientesArchivados(){

    const boton =
        document.getElementById(
            "btnExpandir"
        );

    const botonMovil =
        document.getElementById(
            "btnExpandirMovil"
        );

    const filasDetalle =
        document.querySelectorAll(
            '[id^="detalle-cliente-archivado-"]'
        );


    /* Saber si actualmente toca expandir o colapsar */

    const textoActual =
        boton
            ? boton.textContent.trim()
            : botonMovil
                ? botonMovil.textContent.trim()
                : "Expandir";


    const abrirTodos =
        textoActual === "Expandir";


    filasDetalle.forEach(
        fila => {

            const idUsuario =
                fila.id.replace(
                    "detalle-cliente-archivado-",
                    ""
                );

            const flecha =
                document.getElementById(
                    `flecha-archivado-${idUsuario}`
                );


            if(abrirTodos){

                fila.style.display =
                    "table-row";

                if(flecha){

                    flecha.textContent =
                        "▼";

                }


                mostrarFacturasArchivadasCliente(
                    Number(idUsuario),
                    true
                );


            }else{

                fila.style.display =
                    "none";


                if(flecha){

                    flecha.textContent =
                        "▶";

                }

            }

        }
    );


    /* Cambiar texto de ambos botones */

    const textoBoton =
        abrirTodos
            ? "Colapsar"
            : "Expandir";


    if(boton){

        boton.textContent =
            textoBoton;

    }


    if(botonMovil){

        botonMovil.textContent =
            textoBoton;

    }

}


/* =========================================================
   VOLVER A LISTA DE CLIENTES ARCHIVADOS
========================================================= */

function volverClientesArchivados(){

    clienteArchivadoSeleccionado =
        null;


    document.getElementById(
        "buscar"
    ).value =
        "";


    mostrarListaClientesArchivados();

}


/* =========================================================
   VOLVER DESDE ARCHIVADOS
========================================================= */

function volverArchivados(){

    window.location.href =
        "/add_weight.html";

}

/* =========================================================
   MOSTRAR FACTURAS ARCHIVADAS DEL CLIENTE
========================================================= */
function mostrarFacturasArchivadasCliente(
    idUsuario,
    modoAcordeon = false
){

    const cliente =
        archivadosPorCliente[
            Number(
                idUsuario
            )
        ];

    if(!cliente){

        if(modoAcordeon){
            return;
        }

        volverClientesArchivados();

        return;
    }


    let tabla = null;

    let encabezado = null;

    let contenedor = null;


    if(modoAcordeon){

        contenedor =
            document.getElementById(
                "contenidoModalDetalleArchivado"
            );

        if(!contenedor){
            return;
        }

    }else{

        tabla =
            document.getElementById(
                "tablaArchivados"
            );


        encabezado =
            document.querySelector(
                "table thead"
            );


        encabezado.innerHTML = `

            <tr>

                <th>Cliente</th>

                <th>País de origen</th>

                <th>Peso</th>

                <th>Valor del Peso</th>

                <th>Estado</th>

                <th>Abono</th>

                <th>Saldo</th>

                <th>Fecha</th>

                <th>Archivado</th>

                <th>Acciones</th>

            </tr>

        `;

    }


    const grupos =
        Object.entries(
            cliente.grupos
        );


    if(
        grupos.length === 0
    ){

        if(modoAcordeon){

            contenedor.innerHTML = `

                <div
                    class="sin-archivados"
                >
                    No hay facturas archivadas
                    para este cliente.
                </div>

            `;

        }else{

            tabla.innerHTML = `

                <tr>

                    <td
                        colspan="10"
                        class="sin-archivados"
                    >
                        No hay facturas archivadas
                        para este cliente.
                    </td>

                </tr>

            `;

        }

        return;

    }


    let html = "";

    let htmlModalDocumento = "";


    grupos.forEach(
        ([claveGrupo, grupo]) => {


            const estados =
                Array.from(
                    grupo.estados
                );


            let estadoMostrar =
                "-";


            if(
                estados.length === 1
            ){

                estadoMostrar =
                    traducirEstado(
                        estados[0]
                    );

            }


            if(
                estados.length > 1
            ){

                estadoMostrar =
                    "Varios";

            }


            let saldo =
                grupo.envio_total -
                grupo.total_abonado;


            if(
                saldo < 0
            ){

                saldo = 0;

            }


            const claseSaldo =
                saldo > 0
                    ? "saldo-pendiente"
                    : "saldo-pagado";


            let paisMostrar =
                "-";


            if(
                grupo.pais_origen ===
                "EEUU"
            ){

                paisMostrar =
                    "Estados Unidos";

            }


            if(
                grupo.pais_origen ===
                "COLOMBIA"
            ){

                paisMostrar =
                    "Colombia";

            }


            /*
                NUMERO REAL DE FACTURA

                IMPORTANTE:
                Ya no usamos grupo_compra como
                número visible de factura.

                El número mostrado debe ser
                exactamente el mismo de Gestión
                y del PDF.
            */

            const numeroFactura =
                grupo.numero_factura
                    ? grupo.numero_factura
                    : "-";


            let acciones = "";


            if(
                grupo.grupo_compra
            ){

                acciones = `

                    <button
                        class="btn-detalles-archivado"
                        onclick="verDetallesArchivados(
                            ${cliente.id_usuario},
                            ${grupo.grupo_compra}
                        )"
                    >
                        Detalles
                    </button>


                    <button
                        class="btn-desarchivar"
                        onclick="desarchivarFactura(
                            ${cliente.id_usuario},
                            ${grupo.grupo_compra}
                        )"
                    >
                        Desarchivar
                    </button>


                    <button
                        class="btn-eliminar-archivado"
                        onclick="abrirEliminarArchivado(
                            ${cliente.id_usuario},
                            ${grupo.grupo_compra},
                            null
                        )"
                    >
                        Eliminar
                    </button>

                `;

            }else{

                const pedidoAntiguo =
                    grupo.pedidos &&
                    grupo.pedidos.length > 0
                        ? grupo.pedidos[0]
                        : null;


                if(pedidoAntiguo){

                    acciones = `

                        <button
                            class="btn-eliminar-archivado"
                            onclick="abrirEliminarArchivado(
                                ${cliente.id_usuario},
                                null,
                                ${pedidoAntiguo.id_pedido}
                            )"
                        >
                            Eliminar
                        </button>

                    `;

                }else{

                    acciones = `
                        <span>-</span>
                    `;

                }

            }


            /*
                =================================================
                VISTA MODAL
                IGUAL A GESTION DE PEDIDOS
                =================================================
            */

            if(modoAcordeon){

                htmlModalDocumento += `

                    <section class="ficha-pedido-modal">

                        <div class="ficha-pedido-superior">


                            <div class="ficha-cliente">

                                <div class="ficha-icono-cliente">
                                    👤
                                </div>

                                <div>

                                    <div class="ficha-nombre">
                                        ${cliente.nombre}
                                        ${cliente.apellido}
                                    </div>

                                </div>

                            </div>


                            <div class="ficha-factura">

                                <span>
                                    📄 # Factura
                                </span>

                                <strong>
                                    ${numeroFactura}
                                </strong>

                            </div>


                            <div class="ficha-registro">

                                <span>
                                    📅 Fecha de registro
                                </span>

                                <strong>
                                    ${
                                        grupo.fecha_abono
                                            ? grupo.fecha_abono
                                            : "-"
                                    }
                                </strong>

                            </div>


                        </div>


                        <div class="ficha-datos">


                            <div class="ficha-dato">

                                <span>
                                    ⚖️ Peso
                                </span>

                                <strong>
                                    ${grupo.peso_total} g
                                </strong>

                            </div>


                            <div class="ficha-dato">

                                <span>
                                    💰 Valor del Peso
                                </span>

                                <strong>
                                    ${moneda(
                                        grupo.envio_total
                                    )}
                                </strong>

                            </div>


                            <div class="ficha-dato">

                                <span>
                                    📦 Estado
                                </span>

                                <strong>
                                    ${estadoMostrar}
                                </strong>

                            </div>


                            <div class="ficha-dato">

                                <span>
                                    💵 Abono
                                </span>

                                <strong>
                                    ${moneda(
                                        grupo.total_abonado
                                    )}
                                </strong>

                            </div>


                            <div class="ficha-dato">

                                <span>
                                    💳 Saldo
                                </span>

                                <strong
                                    class="${claseSaldo}"
                                >
                                    ${moneda(
                                        saldo
                                    )}
                                </strong>

                            </div>


                            <div class="ficha-dato">

                                <span>
                                    📅 Fecha
                                </span>

                                <strong>
                                    ${
                                        grupo.fecha_abono
                                            ? grupo.fecha_abono
                                            : "-"
                                    }
                                </strong>

                            </div>


                        </div>


                        <div class="ficha-acciones">

                            <div class="ficha-acciones-titulo">
                                Acciones
                            </div>


                            <div class="ficha-botones">

                                ${acciones}

                            </div>

                        </div>


                        <div class="ficha-registro-archivado">

                            <span>
                                📦 Archivado
                            </span>

                            <strong>
                                ${
                                    grupo.fecha_archivado
                                        ? grupo.fecha_archivado
                                        : "-"
                                }
                            </strong>

                        </div>


                    </section>

                `;

            }


            /*
                =================================================
                TABLA PRINCIPAL DE ARCHIVADOS
                SE CONSERVA
                =================================================
            */

            html += `

                <tr>

                    <td>
                        ${cliente.nombre}
                        ${cliente.apellido}
                    </td>


                    <td>
                        ${paisMostrar}
                    </td>


                    <td>
                        ${grupo.peso_total} g
                    </td>


                    <td>
                        ${moneda(
                            grupo.envio_total
                        )}
                    </td>


                    <td>
                        ${estadoMostrar}
                    </td>


                    <td>
                        ${moneda(
                            grupo.total_abonado
                        )}
                    </td>


                    <td
                        class="${claseSaldo}"
                    >
                        ${moneda(
                            saldo
                        )}
                    </td>


                    <td>
                        ${
                            grupo.fecha_abono
                                ? grupo.fecha_abono
                                : "-"
                        }
                    </td>


                    <td
                        class="fecha-archivado"
                    >
                        ${
                            grupo.fecha_archivado
                                ? grupo.fecha_archivado
                                : "-"
                        }
                    </td>


                    <td>
                        ${acciones}
                    </td>

                </tr>

            `;

        }
    );


    /*
        =================================================
        MOSTRAR FICHAS EN EL MODAL
        =================================================
    */

    if(modoAcordeon){

        contenedor.innerHTML =
            htmlModalDocumento;

    }else{

        tabla.innerHTML =
            html;

    }

}

/* =========================================================
   BUSCADOR
========================================================= */

function filtrar(){

    paginaActualArchivados = 1;

    mostrarListaClientesArchivados();

}

// ======================================================
// 🔹 ABRIR MODAL PARA DESARCHIVAR
// ======================================================

function desarchivarFactura(
    idUsuario,
    grupoCompra
){

    clienteParaDesarchivar =
        Number(idUsuario);

    grupoParaDesarchivar =
        Number(grupoCompra);


    document.getElementById(
        "modalDesarchivar"
    ).classList.add(
        "activo"
    );

}


// ======================================================
// 🔹 CERRAR MODAL DESARCHIVAR
// ======================================================

function cerrarModalDesarchivar(){

    clienteParaDesarchivar =
        null;

    grupoParaDesarchivar =
        null;


    document.getElementById(
        "modalDesarchivar"
    ).classList.remove(
        "activo"
    );

}


// ======================================================
// 🔹 CONFIRMAR DESARCHIVAR
// ======================================================

async function confirmarDesarchivar(){

    if(
        !clienteParaDesarchivar ||
        !grupoParaDesarchivar
    ){
        return;
    }


    const idUsuario =
        clienteParaDesarchivar;

    const grupoCompra =
        grupoParaDesarchivar;


    try{

        const respuesta =
            await fetch(
                "/unarchive-client-orders",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        id_usuario:
                            idUsuario,

                        grupo_compra:
                            grupoCompra
                    })
                }
            );


        const resultado =
            await respuesta.json();


        if(
            !respuesta.ok ||
            !resultado.ok
        ){

            console.error(
                resultado.mensaje ||
                "No se pudo desarchivar la factura."
            );

            return;
        }


        cerrarModalDesarchivar();

        await cargarArchivados();


    }catch(error){

        console.error(
            "Error desarchivando factura:",
            error
        );

    }

}
/* =========================================================
   DETALLES ARCHIVADOS
========================================================= */

function verDetallesArchivados(
    idUsuario,
    grupoCompra
){

    const idCliente =
        Number(
            idUsuario
        );

    const idGrupo =
        Number(
            grupoCompra
        );


    if(
        !Number.isInteger(idCliente) ||
        idCliente <= 0
    ){

        return;

    }


    if(
        !Number.isInteger(idGrupo) ||
        idGrupo <= 0
    ){

        return;

    }


    window.location.href =
        `/details.html?id=${encodeURIComponent(idCliente)}&grupo=${encodeURIComponent(idGrupo)}&archivado=1`;

}

/* =========================================================
   ABRIR MODAL ELIMINAR
========================================================= */

function abrirEliminarArchivado(
    idUsuario,
    grupoCompra,
    idPedido = null
){

    const cliente =
        archivadosPorCliente[
            Number(idUsuario)
        ];


    if(!cliente){
        return;
    }


    clienteArchivadoParaEliminar =
        Number(idUsuario);


    grupoArchivadoParaEliminar =
        grupoCompra !== null &&
        grupoCompra !== undefined
            ? Number(grupoCompra)
            : null;


    pedidoArchivadoParaEliminar =
        idPedido !== null &&
        idPedido !== undefined
            ? Number(idPedido)
            : null;


    let mensaje = "";


    /*
        =====================================================
        FACTURA NORMAL
        =====================================================
    */

    if(
        grupoArchivadoParaEliminar
    ){

        mensaje =
            `¿Desea eliminar definitivamente esta factura archivada de ${cliente.nombre} ${cliente.apellido}? Se eliminarán todos los pedidos y abonos ligados a esta factura.`;

    }


    /*
        =====================================================
        PEDIDO ANTIGUO SIN FACTURA
        =====================================================
    */

    else if(
        pedidoArchivadoParaEliminar
    ){

        mensaje =
            `¿Desea eliminar definitivamente este pedido antiguo archivado de ${cliente.nombre} ${cliente.apellido}?`;

    }


    else{

        return;

    }


    document.getElementById(
        "mensajeEliminarArchivado"
    ).textContent =
        mensaje;


    document.getElementById(
        "modalEliminarArchivado"
    ).style.display =
        "flex";

}


/* =========================================================
   CANCELAR ELIMINACIÓN
========================================================= */

function cancelarEliminarArchivado(){

    clienteArchivadoParaEliminar =
        null;


    grupoArchivadoParaEliminar =
        null;


    pedidoArchivadoParaEliminar =
        null;


    document.getElementById(
        "modalEliminarArchivado"
    ).style.display =
        "none";

}

/* =========================================================
   CONFIRMAR ELIMINACIÓN
========================================================= */

async function confirmarEliminarArchivado(){

    if(
        !clienteArchivadoParaEliminar
    ){
        return;
    }


    const idUsuario =
        clienteArchivadoParaEliminar;


    try{

        const datosEliminar = {
            id_usuario:
                idUsuario
        };


        /*
            Si estamos eliminando una factura normal,
            mandamos grupo_compra.
        */

        if(
            grupoArchivadoParaEliminar !== null &&
            grupoArchivadoParaEliminar !== undefined
        ){

            datosEliminar.grupo_compra =
                grupoArchivadoParaEliminar;

        }


        /*
            Si después usamos esta misma lógica para
            un pedido antiguo sin factura, también
            podremos mandar id_pedido.
        */

        if(
            typeof pedidoArchivadoParaEliminar !== "undefined" &&
            pedidoArchivadoParaEliminar !== null
        ){

            datosEliminar.id_pedido =
                pedidoArchivadoParaEliminar;

        }


        const respuesta =
            await fetch(
                "/delete-archived-client-orders",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify(
                        datosEliminar
                    )
                }
            );


        const resultado =
            await respuesta.json();


        if(
            !respuesta.ok ||
            !resultado.ok
        ){

            console.error(
                resultado.mensaje ||
                "No se pudo eliminar el archivado"
            );

            return;

        }


        cancelarEliminarArchivado();


        await cargarArchivados();


    }catch(error){

        console.error(
            "Error eliminando archivado:",
            error
        );

    }

}


/* =========================================================
   INICIAR
========================================================= */

async function iniciarArchivados(){

    await cargarArchivados();


    const parametrosURL =
        new URLSearchParams(
            window.location.search
        );


    const idClienteURL =
        Number(
            parametrosURL.get("id")
        );


    if(
        Number.isInteger(idClienteURL) &&
        idClienteURL > 0 &&
        archivadosPorCliente[idClienteURL]
    ){

        const clientes =
            obtenerClientesArchivadosFiltrados();


        const indice =
            clientes.findIndex(
                cliente =>
                    Number(
                        cliente.id_usuario
                    ) ===
                    idClienteURL
            );


        if(indice !== -1){

            paginaActualArchivados =
                Math.floor(
                    indice /
                    clientesPorPaginaArchivados
                ) + 1;


            mostrarListaClientesArchivados();


            setTimeout(
                () => {

                    toggleClienteArchivado(
                        idClienteURL
                    );

                },
                0
            );

        }


        window.history.replaceState(
            {},
            "",
            "/archived_orders.html"
        );

    }

}



iniciarArchivados();


