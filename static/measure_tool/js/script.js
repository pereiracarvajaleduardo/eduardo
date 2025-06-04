// static/measure_tool/js/script.js

// MUY IMPORTANTE: Ajusta esta ruta de importación según tu estructura de archivos final.
// Asumiendo: static/measure_tool/js/script.js y static/lib/pdfjs/build/pdf.mjs
import * as pdfjsLib from '/static/lib/pdfjs/build/pdf.mjs'; // Ruta absoluta desde la raíz del sitio

// --- CONFIGURACIÓN INICIAL ---
if (typeof pdfjsLib !== 'undefined') {
    if (typeof PDF_WORKER_URL !== 'undefined' && PDF_WORKER_URL) {
        pdfjsLib.GlobalWorkerOptions.workerSrc = PDF_WORKER_URL;
        console.log("PDF.js workerSrc configurado a:", PDF_WORKER_URL);
    } else {
        console.error("FATAL: PDF_WORKER_URL no está definida por Flask. El visor de PDF no funcionará.");
    }
} else {
    console.error("FATAL: pdfjsLib no está definido. Verifica la importación de PDF.js.");
}

let currentRenderScale = 1.5;
const ZOOM_FACTOR = 0.25;

// --- CONSTANTES ---
const DEFAULT_CURSOR = 'default';
const PRECISE_CURSOR = 'crosshair';
const GRABBING_CURSOR = 'grabbing'; // NUEVO: Cursor para arrastrar
const CALIBRATION_POINT_COLOR = 'rgba(255, 0, 0, 0.7)';
const MEASUREMENT_POINT_COLOR = 'rgba(0, 0, 255, 0.7)';
const MEASUREMENT_LINE_COLOR = 'blue';
const SELECTED_MEASUREMENT_LINE_COLOR = 'purple'; // NUEVO
const SELECTED_MEASUREMENT_POINT_COLOR = 'purple'; // NUEVO
const DRAGGING_POINT_COLOR = 'red'; // NUEVO
const AREA_POLYGON_COLOR_FILL = 'rgba(0, 128, 0, 0.3)';
const AREA_LINE_COLOR = 'green';
const CIRCLE_FILL_COLOR = 'rgba(255, 165, 0, 0.3)';
const CIRCLE_LINE_COLOR = 'orange';
const CANVAS_POINT_RADIUS_BASE = 3;
const DRAG_HANDLE_RADIUS_SCREEN = 8; // NUEVO: Radio para detectar clic en un "handle"
const TEXT_BG_COLOR_MEASUREMENTS = '#ffffffaa';
const TEXT_COLOR_MEASUREMENTS = '#000000';
const TEXT_FONT_MEASUREMENTS = '10px Arial';
const TEXT_PADDING_MEASUREMENTS = 2;


// --- ELEMENTOS DEL DOM ---
const pdfFileInput = document.getElementById('pdf-file-input');
const pdfLoadSection = document.getElementById('pdf-load-section'); // Referencia al contenedor original si aún existe
const canvas = document.getElementById('pdf-canvas');
const context = canvas ? canvas.getContext('2d') : null;
const screenCoordsEl = document.getElementById('screen-coords');
const pdfCoordsEl = document.getElementById('pdf-coords');
const measureDistanceBtn = document.getElementById('measure-distance-btn');
const measureStatusEl = document.getElementById('measure-status');
const measureCanvas = document.getElementById('measure-canvas');
const measureContext = measureCanvas ? measureCanvas.getContext('2d') : null;
const measurementsListEl = document.getElementById('measurements-list');
const clearMeasurementsBtn = document.getElementById('clear-measurements-btn');
const startCalibrateBtn = document.getElementById('start-calibrate-btn');
const calibrationStatusEl = document.getElementById('calibration-status');
const calibrationInputDiv = document.getElementById('calibration-input-div');
const knownLengthInput = document.getElementById('known-length');
const setScaleBtn = document.getElementById('set-scale-btn');
const predefinedScaleSelect = document.getElementById('predefined-scale');
const applyPredefinedScaleBtn = document.getElementById('apply-predefined-scale-btn');
const knownUnitSelect = document.getElementById('known-unit');
const currentScaleInfoEl = document.getElementById('current-scale-info');
const zoomInBtn = document.getElementById('zoom-in-btn');
const zoomOutBtn = document.getElementById('zoom-out-btn');
const zoomLevelInfoEl = document.getElementById('zoom-level-info');
const measureAreaBtn = document.getElementById('measure-area-btn');
const measureCircleBtn = document.getElementById('measure-circle-btn');
const finishShapeBtn = document.getElementById('finish-shape-btn');
const prevPageBtn = document.getElementById('prev-page-btn');
const nextPageBtn = document.getElementById('next-page-btn');
const pageNumEl = document.getElementById('page-num');
const pageCountEl = document.getElementById('page-count');
const goToPageInput = document.getElementById('go-to-page-input');
const goToPageBtn = document.getElementById('go-to-page-btn');

// --- ESTADO DE LA APLICACIÓN ---
let pdfDoc = null;
let currentPageNum = 1;
let pageRendering = false;
let pageNumPending = null;
let currentViewport = null;
let currentPdfSource = null;

let isCalibrating = false;
let calibrationPoints = [];
let scaleFactor = null;
let realWorldUnit = 'mm';

let isMeasuringDistance = false;
let measurementPoints = [];

let isMeasuringArea = false;
let areaPoints = [];

let isMeasuringCircle = false;
let circlePoints = [];

let allMeasurements = [];
let currentMousePosPdf = null;

// NUEVAS VARIABLES DE ESTADO PARA MODIFICACIÓN DE PUNTOS
let currentlySelectedMeasurementIndex = -1;
let currentlySelectedPointIndex = -1;
let isDraggingPoint = false;
let originalDragPointPdf = null;

// --- FUNCIONES DE PAGINACIÓN ---
function updatePaginationControls() {
    if (!pdfDoc || !pageNumEl || !pageCountEl || !prevPageBtn || !nextPageBtn || !goToPageInput || !goToPageBtn) {
        if(pageNumEl) pageNumEl.textContent = "-";
        if(pageCountEl) pageCountEl.textContent = "-";
        if(prevPageBtn) prevPageBtn.disabled = true;
        if(nextPageBtn) nextPageBtn.disabled = true;
        if(goToPageInput) { goToPageInput.value = ""; goToPageInput.disabled = true; }
        if(goToPageBtn) goToPageBtn.disabled = true;
        return;
    }
    pageNumEl.textContent = currentPageNum;
    pageCountEl.textContent = pdfDoc.numPages;
    prevPageBtn.disabled = (currentPageNum <= 1);
    nextPageBtn.disabled = (currentPageNum >= pdfDoc.numPages);
    goToPageInput.max = pdfDoc.numPages;
    goToPageInput.min = 1;
    goToPageInput.disabled = false;
    goToPageBtn.disabled = false;
}

// --- FUNCIONES DE RENDERIZADO DEL PDF ---
function renderPage(num) {
    if (!pdfDoc) {
        console.warn("renderPage llamado pero pdfDoc es null.");
        pageRendering = false;
        updatePaginationControls();
        return;
    }
    pageRendering = true;
    currentPageNum = num;
    console.log(`Renderizando página ${num} con escala ${currentRenderScale}`);
    updatePaginationControls();

    pdfDoc.getPage(num).then(function(page) {
        currentViewport = page.getViewport({ scale: currentRenderScale });
        if (canvas) {
            canvas.height = currentViewport.height;
            canvas.width = currentViewport.width;
        }
        if (measureCanvas) {
            measureCanvas.height = currentViewport.height;
            measureCanvas.width = currentViewport.width;
        }

        const renderContext = { canvasContext: context, viewport: currentViewport };
        const renderTask = page.render(renderContext);

        renderTask.promise.then(function() {
            console.log(`Página ${num} renderizada.`);
            pageRendering = false;
            if (pageNumPending !== null) {
                const pending = pageNumPending;
                pageNumPending = null;
                renderPage(pending);
            }
            redrawAllScreenElements();
            updateZoomLevelInfo();
        }).catch(function(error) {
            console.error("Error AL RENDERIZAR la página:", error);
            pageRendering = false;
            updatePaginationControls();
        });
    }).catch(function(error) {
        console.error("Error AL OBTENER la página:", error);
        pageRendering = false;
        updatePaginationControls();
    });
}

function queueRenderPage(num) {
    if (pageRendering) {
        pageNumPending = num;
    } else {
        renderPage(num);
    }
}

function resetApplicationState() {
    pdfDoc = null;
    currentPageNum = 1;

    scaleFactor = null;
    realWorldUnit = knownUnitSelect ? knownUnitSelect.value : 'mm';
    if(currentScaleInfoEl) currentScaleInfoEl.textContent = "No calibrada";
    if(calibrationStatusEl) calibrationStatusEl.textContent = 'Esperando inicio...';
    if(calibrationInputDiv) calibrationInputDiv.style.display = 'none';
    calibrationPoints = [];

    deactivateAllModes(); // Esto también reseteará los estados de edición de puntos

    measurementPoints = [];
    areaPoints = [];
    circlePoints = [];
    allMeasurements = [];

    clearMeasureCanvas();
    updateMeasurementsList();
    updateZoomLevelInfo();
    updatePaginationControls();

    if(measureCanvas) {
        measureCanvas.style.pointerEvents = 'none';
        measureCanvas.style.cursor = DEFAULT_CURSOR;
    }
    console.log('Estado de la aplicación reseteado.');
}

function loadAndRenderPdf(pdfSource) {
    if (!pdfSource) {
        console.warn("loadAndRenderPdf llamado sin fuente de PDF.");
        // Mostrar el input de carga si está oculto y es el principal
        const pdfLoadSectionTop = document.getElementById('pdf-load-section-top'); // Asumiendo ID del toolbar
        if(pdfLoadSectionTop) pdfLoadSectionTop.style.display = 'block';
        else if(pdfLoadSection) pdfLoadSection.classList.remove('file-input-hidden');
        updatePaginationControls();
        return;
    }

    if (currentPdfSource && typeof currentPdfSource === 'string' && currentPdfSource.startsWith('blob:')) {
        URL.revokeObjectURL(currentPdfSource);
    }
    currentPdfSource = pdfSource;

    resetApplicationState();

    const loadingTask = pdfjsLib.getDocument(pdfSource);
    loadingTask.promise.then(function(pdfDoc_) {
        pdfDoc = pdfDoc_;
        console.log('PDF cargado:', pdfDoc.numPages, 'páginas.');
        currentPageNum = 1;
        if(measureCanvas) measureCanvas.style.pointerEvents = 'auto';
        updatePaginationControls();
        queueRenderPage(currentPageNum);
        
        // Ocultar inputs de carga
        const pdfLoadSectionTop = document.getElementById('pdf-load-section-top');
        if(pdfLoadSectionTop) pdfLoadSectionTop.style.display = 'none';
        if(pdfLoadSection) pdfLoadSection.classList.add('file-input-hidden');

    }).catch(function(reason) {
        console.error('Error al cargar el PDF:', reason);
        alert('Error al cargar el PDF: ' + (reason.message || 'Error desconocido. Revisa la consola.'));
        resetApplicationState();
        const pdfLoadSectionTop = document.getElementById('pdf-load-section-top');
        if(pdfLoadSectionTop) pdfLoadSectionTop.style.display = 'block';
        else if(pdfLoadSection) pdfLoadSection.classList.remove('file-input-hidden');
    });
}

// --- UTILIDADES DE COORDENADAS ---
function getPdfPoint(clientX, clientY) { // Cambiado a clientX, clientY
    if (!currentViewport || !measureCanvas) return null;
    const rect = measureCanvas.getBoundingClientRect();
    const canvasX = clientX - rect.left;
    const canvasY = clientY - rect.top;
    const pdfPoint = currentViewport.convertToPdfPoint(canvasX, canvasY);
    return { x: pdfPoint[0], y: pdfPoint[1] };
}

function getScreenPoint(pdfPoint) {
    if (!currentViewport) return null;
    const screenPoint = currentViewport.convertToViewportPoint(pdfPoint.x, pdfPoint.y);
    return { x: screenPoint[0], y: screenPoint[1] };
}

function getScreenPoints(pdfPoints) {
    return pdfPoints.map(p => getScreenPoint(p));
}

// --- LÓGICA DE DIBUJO EN MEASURECANVAS ---
function clearMeasureCanvas() {
    if (measureContext && measureCanvas) {
        measureContext.clearRect(0, 0, measureCanvas.width, measureCanvas.height);
    }
}

function drawPoint(ctx, screenPoint, color, radius = CANVAS_POINT_RADIUS_BASE) {
    if (!screenPoint) return;
    // El radio ahora se escala directamente en la función, no se ajusta por currentRenderScale aquí
    // sino que el valor de `radius` que se pasa ya debería estar escalado si es un "handle"
    const finalRadius = (radius === DRAG_HANDLE_RADIUS_SCREEN)
                        ? DRAG_HANDLE_RADIUS_SCREEN // Usar el radio de handle directamente (ya es en px de pantalla)
                        : (CANVAS_POINT_RADIUS_BASE / currentRenderScale * 1.5); // Escalar el radio base

    ctx.beginPath();
    ctx.arc(screenPoint.x, screenPoint.y, finalRadius, 0, 2 * Math.PI, false);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.lineWidth = 1;
    ctx.strokeStyle = 'black'; // Un borde para mejor visibilidad de los puntos
    ctx.stroke();
}

function drawLine(ctx, screenP1, screenP2, color, lineWidth = 2) {
    if (!screenP1 || !screenP2) return;
    ctx.beginPath();
    ctx.moveTo(screenP1.x, screenP1.y);
    ctx.lineTo(screenP2.x, screenP2.y);
    ctx.strokeStyle = color;
    ctx.lineWidth = lineWidth / currentRenderScale * 1.5;
    ctx.stroke();
}

function drawPolygon(ctx, screenPoints, lineColor, fillColor, lineWidth = 2,closePath = true) {
    if (!screenPoints || screenPoints.length < 2) return;
    ctx.beginPath();
    ctx.moveTo(screenPoints[0].x, screenPoints[0].y);
    for (let i = 1; i < screenPoints.length; i++) {
        ctx.lineTo(screenPoints[i].x, screenPoints[i].y);
    }
    if (closePath && screenPoints.length > 2) {
        ctx.closePath();
    }
    if (fillColor) {
        ctx.fillStyle = fillColor;
        ctx.fill();
    }
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = lineWidth / currentRenderScale * 1.5;
    ctx.stroke();
}

function drawCircle(ctx, screenCenter, screenRadius, lineColor, fillColor, lineWidth = 2) {
    if (!screenCenter || screenRadius <= 0) return;
    ctx.beginPath();
    ctx.arc(screenCenter.x, screenCenter.y, screenRadius, 0, 2 * Math.PI, false);
    if (fillColor) {
        ctx.fillStyle = fillColor;
        ctx.fill();
    }
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = lineWidth / currentRenderScale * 1.5;
    ctx.stroke();
}

function drawMeasurementTextWithBackground(ctx, text, screenPoint, options = {}) {
    if (!screenPoint || !text) return;
    const font = options.font || TEXT_FONT_MEASUREMENTS;
    const textColor = options.textColor || TEXT_COLOR_MEASUREMENTS;
    const bgColor = options.bgColor || TEXT_BG_COLOR_MEASUREMENTS;
    const padding = options.padding || TEXT_PADDING_MEASUREMENTS;
    const textAlign = options.textAlign || 'center';
    const textBaseline = options.textBaseline || 'bottom';
    const offsetY = options.offsetY || -10; // Ajustado para que no esté tan pegado

    ctx.font = font;
    ctx.textAlign = textAlign;
    ctx.textBaseline = textBaseline;

    const textMetrics = ctx.measureText(text);
    const textWidth = textMetrics.width;
    // Una aproximación más robusta para la altura del texto
    const textHeight = (textMetrics.actualBoundingBoxAscent + textMetrics.actualBoundingBoxDescent) || parseInt(font, 10) * 1.2;


    const bgX = screenPoint.x - (textAlign === 'center' ? textWidth / 2 : (textAlign === 'right' ? textWidth : 0)) - padding;
    const bgY = screenPoint.y + offsetY - textHeight - padding;
    const bgWidth = textWidth + 2 * padding;
    const bgHeight = textHeight + 2 * padding;

    ctx.fillStyle = bgColor;
    ctx.fillRect(bgX, bgY, bgWidth, bgHeight);

    ctx.fillStyle = textColor;
    ctx.fillText(text, screenPoint.x, screenPoint.y + offsetY);
}

// MODIFICADO: redrawAllScreenElements para handles y selección
function redrawAllScreenElements() {
    if (!measureContext || !currentViewport) return;
    clearMeasureCanvas();

    // 1. Dibujar mediciones completadas
    allMeasurements.forEach((m, index) => {
        if (m.pageNum !== currentPageNum) return;

        const screenPoints = getScreenPoints(m.pointsPdf);
        // m.screenPoints = screenPoints; // Ya no es necesario almacenar screenPoints en el objeto m directamente si se recalculan aquí

        let baseLineColor = MEASUREMENT_LINE_COLOR;
        let basePointColor = MEASUREMENT_POINT_COLOR;
        let pointDisplayRadius = CANVAS_POINT_RADIUS_BASE; // Radio para dibujar puntos normales

        if (m.type === 'distance') { // Lógica de resaltado y handles solo para distancia por ahora
            if (index === currentlySelectedMeasurementIndex) {
                baseLineColor = SELECTED_MEASUREMENT_LINE_COLOR;
                basePointColor = SELECTED_MEASUREMENT_POINT_COLOR; // Color para handles de la línea seleccionada
                pointDisplayRadius = DRAG_HANDLE_RADIUS_SCREEN; // Usar radio de handle para los puntos de la línea seleccionada
            }

            if (screenPoints && screenPoints.length === 2) {
                drawLine(measureContext, screenPoints[0], screenPoints[1], baseLineColor);
                screenPoints.forEach((p, pIndex) => {
                    let currentHandleColor = basePointColor;
                    if (index === currentlySelectedMeasurementIndex && pIndex === currentlySelectedPointIndex && isDraggingPoint) {
                        currentHandleColor = DRAGGING_POINT_COLOR; // Punto específico que se está arrastrando
                    }
                    // Pasar DRAG_HANDLE_RADIUS_SCREEN o CANVAS_POINT_RADIUS_BASE según si es un handle o no.
                    // La función drawPoint ahora escala internamente basado en el radio que recibe.
                    drawPoint(measureContext, p, currentHandleColor, (index === currentlySelectedMeasurementIndex) ? DRAG_HANDLE_RADIUS_SCREEN : CANVAS_POINT_RADIUS_BASE);
                });
                const midPoint = { x: (screenPoints[0].x + screenPoints[1].x) / 2, y: (screenPoints[0].y + screenPoints[1].y) / 2 };
                drawMeasurementTextWithBackground(measureContext, `${m.value.toFixed(2)} ${m.unit}`, midPoint);
            }
        } else if (m.type === 'area' && screenPoints && screenPoints.length > 2) {
            drawPolygon(measureContext, screenPoints, AREA_LINE_COLOR, AREA_POLYGON_COLOR_FILL);
            screenPoints.forEach(p => drawPoint(measureContext, p, MEASUREMENT_POINT_COLOR, CANVAS_POINT_RADIUS_BASE));
            let centerX = 0, centerY = 0; screenPoints.forEach(p => { centerX += p.x; centerY += p.y; });
            const center = { x: centerX / screenPoints.length, y: centerY / screenPoints.length };
            drawMeasurementTextWithBackground(measureContext, `${m.value.toFixed(2)} ${m.unit}\u00B2`, center);
        } else if (m.type === 'circle' && m.centerPdf && typeof m.radiusPdf !== 'undefined' && screenPoints && screenPoints.length === 3) {
            const screenCenter = getScreenPoint(m.centerPdf);
            // Recalcular screenRadius basado en la escala actual para la visualización
            const p1Radius = { x: m.centerPdf.x + m.radiusPdf, y: m.centerPdf.y };
            const sp1Radius = getScreenPoint(p1Radius);
            const visualScreenRadius = Math.sqrt(Math.pow(sp1Radius.x - screenCenter.x, 2) + Math.pow(sp1Radius.y - screenCenter.y, 2));

            if (screenCenter && visualScreenRadius > 0) {
                 drawCircle(measureContext, screenCenter, visualScreenRadius, CIRCLE_LINE_COLOR, CIRCLE_FILL_COLOR);
                 m.pointsPdf.forEach(p => drawPoint(measureContext, getScreenPoint(p), MEASUREMENT_POINT_COLOR, CANVAS_POINT_RADIUS_BASE));
                 drawMeasurementTextWithBackground(measureContext, `R: ${m.radiusDisplay.toFixed(2)} ${m.unit}\nA: ${m.value.toFixed(2)} ${m.unit}\u00B2`, screenCenter);
            }
        }
    });

    // 2. Dibujar puntos de calibración en curso
    if (isCalibrating && calibrationPoints.length > 0) {
        // (código existente para dibujar calibración)
        const screenCalPoints = getScreenPoints(calibrationPoints);
        screenCalPoints.forEach(p => drawPoint(measureContext, p, CALIBRATION_POINT_COLOR, CANVAS_POINT_RADIUS_BASE));
        if (screenCalPoints.length === 1 && currentMousePosPdf) {
            drawLine(measureContext, screenCalPoints[0], getScreenPoint(currentMousePosPdf), CALIBRATION_POINT_COLOR, 1);
        }
    }

    // 3. Dibujar medición en curso (nueva)
    // MODIFICADO: Solo dibujar previsualización de nueva medición si NO estamos arrastrando un punto existente
    if (!isDraggingPoint) {
        if (isMeasuringDistance && measurementPoints.length > 0) { // Asegurarse que hay al menos un punto para la previsualización
            const screenMeasurementPoints = getScreenPoints(measurementPoints);
            screenMeasurementPoints.forEach(p => drawPoint(measureContext, p, MEASUREMENT_POINT_COLOR, CANVAS_POINT_RADIUS_BASE));
            if (screenMeasurementPoints.length === 1 && currentMousePosPdf) {
                drawLine(measureContext, screenMeasurementPoints[0], getScreenPoint(currentMousePosPdf), MEASUREMENT_LINE_COLOR, 1);
            }
        } else if (isMeasuringArea && areaPoints.length > 0) {
            // (código existente para dibujar previsualización de área)
            const screenAreaPoints = getScreenPoints(areaPoints);
            screenAreaPoints.forEach(p => drawPoint(measureContext, p, MEASUREMENT_POINT_COLOR, CANVAS_POINT_RADIUS_BASE));
            if (currentMousePosPdf) { // Siempre mostrar previsualización al siguiente punto
                const tempPoints = [...screenAreaPoints, getScreenPoint(currentMousePosPdf)];
                 drawPolygon(measureContext, tempPoints, AREA_LINE_COLOR, null, 1, areaPoints.length >=2); // No rellenar previsualización
            }
        } else if (isMeasuringCircle && circlePoints.length > 0) {
            // (código existente para dibujar previsualización de círculo)
            const screenCirclePoints = getScreenPoints(circlePoints);
            screenCirclePoints.forEach(p => drawPoint(measureContext, p, MEASUREMENT_POINT_COLOR, CANVAS_POINT_RADIUS_BASE));
            if (screenCirclePoints.length === 1 && currentMousePosPdf) {
                drawLine(measureContext, screenCirclePoints[0], getScreenPoint(currentMousePosPdf), CIRCLE_LINE_COLOR, 1);
            } else if (screenCirclePoints.length === 2 && currentMousePosPdf) {
                const tempPdfPoints = [...circlePoints, currentMousePosPdf];
                const circleParams = calculateCircleFrom3Points(tempPdfPoints[0], tempPdfPoints[1], tempPdfPoints[2]);
                if (circleParams) {
                    const screenCenter = getScreenPoint(circleParams.centerPdf);
                    const p1Radius = { x: circleParams.centerPdf.x + circleParams.radiusPdf, y: circleParams.centerPdf.y };
                    const sp1Radius = getScreenPoint(p1Radius);
                    const visualScreenRadius = Math.sqrt(Math.pow(sp1Radius.x - screenCenter.x, 2) + Math.pow(sp1Radius.y - screenCenter.y, 2));
                    if (screenCenter && visualScreenRadius > 0) {
                        drawCircle(measureContext, screenCenter, visualScreenRadius, CIRCLE_LINE_COLOR, null, 1); // No rellenar previsualización
                    }
                }
            }
        }
    }
}


function updateMeasurementsList() {
    if (!measurementsListEl) return;
    measurementsListEl.innerHTML = '';
    allMeasurements.forEach((m, index) => {
        const listItem = document.createElement('li');
        // Aplicar clases de Bootstrap si estás usando la lista en el HTML que me pasaste
        listItem.className = 'list-group-item list-group-item-action list-group-item-sm d-flex justify-content-between align-items-center';
        let textContent = `<b>${index + 1}</b> (P${m.pageNum}): `;
        if (m.type === 'distance') {
            textContent += `Dist. ${m.value.toFixed(2)} ${m.unit}`;
        } else if (m.type === 'area') {
            textContent += `Área ${m.value.toFixed(2)} ${m.unit}\u00B2`;
        } else if (m.type === 'circle') {
            textContent += `Círculo R:${m.radiusDisplay.toFixed(2)}, A:${m.value.toFixed(2)} ${m.unit}\u00B2`;
        }
        listItem.innerHTML = textContent; // Usar innerHTML por la etiqueta <b>
        measurementsListEl.appendChild(listItem);
    });
}

// --- MANEJO DE MODOS ---
function deactivateAllModes() {
    isCalibrating = false;
    isMeasuringDistance = false;
    isMeasuringArea = false;
    isMeasuringCircle = false;

    currentlySelectedMeasurementIndex = -1;
    currentlySelectedPointIndex = -1;
    if (isDraggingPoint) {
        document.removeEventListener('mousemove', handleMouseMoveDocument);
        document.removeEventListener('mouseup', handleMouseUpDocument);
        isDraggingPoint = false;
    }

    calibrationPoints = [];
    measurementPoints = [];
    areaPoints = [];
    circlePoints = [];

    if (measureStatusEl) measureStatusEl.textContent = 'Selecciona una herramienta.';
    
    // Restaurar texto y quitar clase 'active' de botones de modo
    const modeButtons = [
        { btn: measureDistanceBtn, text: 'Distancia' }, // Asegúrate que estos textos coincidan con tu HTML o lo deseado
        { btn: measureAreaBtn, text: 'Área' },
        { btn: measureCircleBtn, text: 'Círculo' },
        { btn: startCalibrateBtn, text: 'Calibrar' }
    ];
    modeButtons.forEach(item => {
        if (item.btn) {
            item.btn.classList.remove('active');
            item.btn.textContent = item.text;
        }
    });

    if (finishShapeBtn) finishShapeBtn.style.display = 'none';
    if (measureCanvas) measureCanvas.style.cursor = DEFAULT_CURSOR;
    // No llamar a redrawAllScreenElements aquí, se hará externamente si es necesario.
}

// Las funciones activate...Mode ya llaman a deactivateAllModes() primero.
// Y establecen el texto y la clase 'active' para el botón correspondiente.
// Ejemplo:
function activateMeasureDistanceMode() {
    if (!scaleFactor && !isCalibrating) { // Permitir calibrar sin escala
        alert("Por favor, calibra la escala primero o selecciona una escala predefinida.");
        return;
    }
    deactivateAllModes();
    isMeasuringDistance = true;
    if (measureStatusEl) measureStatusEl.textContent = 'Distancia: Clic en dos puntos.';
    if (measureDistanceBtn) {
        measureDistanceBtn.classList.add('active');
        measureDistanceBtn.textContent = 'Cancel. Dist.';
    }
    if (measureCanvas) measureCanvas.style.cursor = PRECISE_CURSOR;
    redrawAllScreenElements(); // Redibujar para limpiar y reflejar el nuevo modo
}
// (Asegúrate que tus otras funciones activate...Mode sigan un patrón similar para el texto del botón y .active)
function activateCalibrationMode() { /* ... (tu código actual, asegurando .active y cambio de texto) ... */ 
    deactivateAllModes(); isCalibrating = true; if (measureStatusEl) measureStatusEl.textContent = 'Calibración: Clic en dos puntos.'; if (startCalibrateBtn) { startCalibrateBtn.classList.add('active'); startCalibrateBtn.textContent = 'Cancel. Cal.';} if (calibrationInputDiv) calibrationInputDiv.style.display = 'none'; if (measureCanvas) measureCanvas.style.cursor = PRECISE_CURSOR; redrawAllScreenElements();
}
function activateMeasureAreaMode() { /* ... (tu código actual, asegurando .active y cambio de texto) ... */
    if (!scaleFactor) { alert("Por favor, calibra la escala primero."); return; } deactivateAllModes(); isMeasuringArea = true; if (measureStatusEl) measureStatusEl.textContent = 'Área: Clic para puntos (mín. 3).'; if (measureAreaBtn) {measureAreaBtn.classList.add('active'); measureAreaBtn.textContent = 'Cancel. Área';} if (finishShapeBtn) finishShapeBtn.style.display = 'inline-block'; if (measureCanvas) measureCanvas.style.cursor = PRECISE_CURSOR; redrawAllScreenElements();
}
function activateMeasureCircleMode() { /* ... (tu código actual, asegurando .active y cambio de texto) ... */
    if (!scaleFactor) { alert("Por favor, calibra la escala primero."); return; } deactivateAllModes(); isMeasuringCircle = true; if (measureStatusEl) measureStatusEl.textContent = 'Círculo: Clic en 3 puntos.'; if (measureCircleBtn) {measureCircleBtn.classList.add('active'); measureCircleBtn.textContent = 'Cancel. Círculo';} if (measureCanvas) measureCanvas.style.cursor = PRECISE_CURSOR; redrawAllScreenElements();
}


// --- CÁLCULOS GEOMÉTRICOS ---
// (Sin cambios aquí)
function calculateDistance(pdfP1, pdfP2) { return Math.sqrt(Math.pow(pdfP2.x - pdfP1.x, 2) + Math.pow(pdfP2.y - pdfP1.y, 2)); }
function convertToRealWorld(pdfValue, sf, unit, isArea = false) { if (!sf && sf !== 0) return { value: pdfValue, unit: 'unid.PDF' + (isArea ? '²' : '') }; const conv = isArea ? sf * sf : sf; return { value: pdfValue * conv, unit: unit }; }
function calculateAreaShoelace(pdfPoints) { let area = 0; const n = pdfPoints.length; for (let i = 0; i < n; i++) { const p1 = pdfPoints[i]; const p2 = pdfPoints[(i + 1) % n]; area += (p1.x * p2.y) - (p2.x * p1.y); } return Math.abs(area / 2); }
function calculateCircleFrom3Points(p1, p2, p3) { const D = 2*(p1.x*(p2.y-p3.y)+p2.x*(p3.y-p1.y)+p3.x*(p1.y-p2.y)); if(Math.abs(D)<1e-8)return null; const p1sq=p1.x*p1.x+p1.y*p1.y; const p2sq=p2.x*p2.x+p2.y*p2.y; const p3sq=p3.x*p3.x+p3.y*p3.y; const cX=(p1sq*(p2.y-p3.y)+p2sq*(p3.y-p1.y)+p3sq*(p1.y-p2.y))/D; const cY=(p1sq*(p3.x-p2.x)+p2sq*(p1.x-p3.x)+p3sq*(p2.x-p1.x))/D; const rad=calculateDistance({x:cX,y:cY},p1); return{centerPdf:{x:cX,y:cY},radiusPdf:rad}; }


// --- MANEJADORES DE EVENTOS ---

// Listener de mousemove en canvas (como estaba, pero condicionado por !isDraggingPoint)
if (measureCanvas) {
    measureCanvas.addEventListener('mousemove', (event) => {
        if (!pdfDoc || !currentViewport) return;
        // ... (código para obtener coordenadas y currentMousePosPdf)
        const rect = measureCanvas.getBoundingClientRect();
        const x = event.clientX - rect.left; const y = event.clientY - rect.top;
        if (screenCoordsEl) screenCoordsEl.textContent = `${x.toFixed(0)}, ${y.toFixed(0)}`;
        const pdfPoint = currentViewport.convertToPdfPoint(x, y);
        if (pdfCoordsEl) pdfCoordsEl.textContent = `${pdfPoint[0].toFixed(2)}, ${pdfPoint[1].toFixed(2)}`;
        currentMousePosPdf = { x: pdfPoint[0], y: pdfPoint[1] };

        if (!isDraggingPoint && (
            (isMeasuringDistance && measurementPoints.length === 1) ||
            (isMeasuringArea && areaPoints.length > 0) ||
            (isCalibrating && calibrationPoints.length === 1) ||
            (isMeasuringCircle && (circlePoints.length === 1 || circlePoints.length === 2))
           )) {
            redrawAllScreenElements();
        }
    });

    measureCanvas.addEventListener('mousedown', handleMouseDownOnCanvas);
}

// FUNCIONES MANEJADORAS PARA DRAG AND DROP (como en la respuesta anterior)
function handleMouseDownOnCanvas(event) {
    if (!pdfDoc || !currentViewport || event.button !== 0) return;
    const clickPdfPoint = getPdfPoint(event.clientX, event.clientY);
    if (!clickPdfPoint) return;

    const noMeasurementModeActive = !isCalibrating && !isMeasuringDistance && !isMeasuringArea && !isMeasuringCircle;

    if (noMeasurementModeActive) {
        let clickedOnHandle = false;
        for (let i = allMeasurements.length - 1; i >= 0; i--) {
            const measurement = allMeasurements[i];
            if (measurement.pageNum !== currentPageNum || measurement.type !== 'distance') continue;

            const screenPoints = getScreenPoints(measurement.pointsPdf);
            if (!screenPoints || screenPoints.length !== 2) continue; // Asegurar que tenemos puntos de pantalla

            for (let j = 0; j < screenPoints.length; j++) {
                const sp = screenPoints[j];
                const clickScreenPoint = getScreenPoint(clickPdfPoint); // Convertir el clic a pantalla
                if (!clickScreenPoint) continue;

                const distanceToHandle = Math.sqrt(Math.pow(clickScreenPoint.x - sp.x, 2) + Math.pow(clickScreenPoint.y - sp.y, 2));

                if (distanceToHandle < DRAG_HANDLE_RADIUS_SCREEN) {
                    isDraggingPoint = true;
                    currentlySelectedMeasurementIndex = i;
                    currentlySelectedPointIndex = j;
                    originalDragPointPdf = { ...measurement.pointsPdf[j] };
                    if(measureCanvas) measureCanvas.style.cursor = GRABBING_CURSOR;
                    
                    document.addEventListener('mousemove', handleMouseMoveDocument);
                    document.addEventListener('mouseup', handleMouseUpDocument);
                    
                    redrawAllScreenElements(); // Para resaltar inmediatamente
                    event.preventDefault();
                    clickedOnHandle = true;
                    return; 
                }
            }
        }
        if (!clickedOnHandle && currentlySelectedMeasurementIndex !== -1) { // Si se hizo clic fuera de un handle pero algo estaba seleccionado
            currentlySelectedMeasurementIndex = -1; // Deseleccionar
            currentlySelectedPointIndex = -1;
            redrawAllScreenElements();
        }
        // Si no hay modo activo y no se hizo clic en handle, no hacer nada más en este mousedown.
        // Esto evita que se creen puntos si el usuario solo quiere deseleccionar haciendo clic en un espacio vacío.
        return; 
    }

    // --- Lógica para colocar nuevos puntos (si un modo de creación está activo) ---
    if (isCalibrating) {
        calibrationPoints.push(clickPdfPoint);
        if (calibrationPoints.length === 2) {
            if (calibrationInputDiv) calibrationInputDiv.style.display = 'block';
            if (measureStatusEl) measureStatusEl.textContent = 'Calibración: Ingresa longitud y unidad.';
            // No desactivar modo aquí, se hace al presionar "Fijar Escala"
        }
    } else if (isMeasuringDistance) {
        measurementPoints.push(clickPdfPoint);
        if (measurementPoints.length === 2) {
            const pdfDist = calculateDistance(measurementPoints[0], measurementPoints[1]);
            const realWorld = convertToRealWorld(pdfDist, scaleFactor, realWorldUnit);
            allMeasurements.push({ type: 'distance', pointsPdf: [...measurementPoints], value: realWorld.value, unit: realWorld.unit, pageNum: currentPageNum });
            updateMeasurementsList();
            measurementPoints = []; // Preparar para la siguiente, si el usuario quiere.
            // IMPORTANTE: No desactivar isMeasuringDistance aquí para permitir mediciones consecutivas
            // El usuario lo desactiva haciendo clic de nuevo en el botón "Cancel. Dist."
            // O, si queremos que se desactive después de cada línea:
            // deactivateAllModes(); // Esto deseleccionaría el botón y cambiaría el texto
        }
    } else if (isMeasuringArea) {
        areaPoints.push(clickPdfPoint);
        if (areaPoints.length >= 3 && measureStatusEl) measureStatusEl.textContent = 'Área: Más puntos o "Finalizar".';
    } else if (isMeasuringCircle) {
        circlePoints.push(clickPdfPoint);
        if (circlePoints.length === 3) {
            const circleParams = calculateCircleFrom3Points(circlePoints[0], circlePoints[1], circlePoints[2]);
            if (circleParams) {
                const realWorldRadius = convertToRealWorld(circleParams.radiusPdf, scaleFactor, realWorldUnit);
                const realWorldArea = convertToRealWorld(Math.PI * Math.pow(circleParams.radiusPdf, 2), scaleFactor, realWorldUnit, true);
                allMeasurements.push({ /* ... datos del círculo ... */ type: 'circle', pointsPdf: [...circlePoints], centerPdf: circleParams.centerPdf, radiusPdf: circleParams.radiusPdf, radiusDisplay: realWorldRadius.value, value: realWorldArea.value, unit: realWorldRadius.unit, pageNum: currentPageNum, originalScaleAtMeasurement: currentViewport.scale });
                updateMeasurementsList();
                circlePoints = [];
                // IMPORTANTE: No desactivar isMeasuringCircle aquí para permitir mediciones consecutivas
                // O, si queremos que se desactive:
                // deactivateAllModes();
            } else {
                alert("No se pudo calcular el círculo.");
                circlePoints = [];
            }
        }
    }
    redrawAllScreenElements();
}

function handleMouseMoveDocument(event) {
    if (!isDraggingPoint) return;
    event.preventDefault();

    const currentPdfMousePoint = getPdfPoint(event.clientX, event.clientY);
    if (!currentPdfMousePoint) return;

    if (currentlySelectedMeasurementIndex > -1 && currentlySelectedPointIndex > -1) {
        const measurement = allMeasurements[currentlySelectedMeasurementIndex];
        measurement.pointsPdf[currentlySelectedPointIndex].x = currentPdfMousePoint.x;
        measurement.pointsPdf[currentlySelectedPointIndex].y = currentPdfMousePoint.y;

        if (measurement.type === 'distance') {
            const pdfDist = calculateDistance(measurement.pointsPdf[0], measurement.pointsPdf[1]);
            const realWorld = convertToRealWorld(pdfDist, scaleFactor, measurement.unit);
            measurement.value = realWorld.value;
        }
        redrawAllScreenElements();
    }
}

function handleMouseUpDocument(event) {
    if (!isDraggingPoint) return;
    event.preventDefault();
    
    const anyMeasurementModeActive = isMeasuringDistance || isMeasuringArea || isMeasuringCircle || isCalibrating;
    if(measureCanvas) measureCanvas.style.cursor = anyMeasurementModeActive ? PRECISE_CURSOR : DEFAULT_CURSOR;
    
    // isDraggingPoint se pone a false DESPUÉS de quitar listeners y recalcular
    // para que redrawAllScreenElements todavía sepa que se estaba arrastrando si es necesario

    document.removeEventListener('mousemove', handleMouseMoveDocument);
    document.removeEventListener('mouseup', handleMouseUpDocument);

    if (currentlySelectedMeasurementIndex > -1) {
        const measurement = allMeasurements[currentlySelectedMeasurementIndex];
        // El punto ya fue actualizado en pointsPdf por handleMouseMoveDocument.
        // Recalculamos y guardamos el valor final.
        if (measurement.type === 'distance') {
            const pdfDist = calculateDistance(measurement.pointsPdf[0], measurement.pointsPdf[1]);
            const realWorld = convertToRealWorld(pdfDist, scaleFactor, measurement.unit);
            measurement.value = realWorld.value;
        }
        updateMeasurementsList();
        // La medición permanece "seleccionada" visualmente (el índice no se resetea) hasta
        // que se haga clic en otro lado o se inicie un nuevo modo.
    }
    isDraggingPoint = false; // Ahora sí, finalizar el estado de arrastre
    redrawAllScreenElements();
}


// --- MANEJADORES DE EVENTOS PARA BOTONES DE UI ---
// (Función setupModeButton y listeners de botones como en la respuesta anterior,
//  asegurando que llamen a deactivateAllModes() correctamente para el toggle)

function setupModeButton(button, activateFunction, modeName, activeText, inactiveText) {
    if (!button) return;
    button.addEventListener('click', () => {
        // Comprobar si el modo que este botón activa ya está activo
        let وضعحالیمربوطهفعالاست = false;
        if (modeName === 'distance') وضعحالیمربوطهفعالاست = isMeasuringDistance;
        else if (modeName === 'area') وضعحالیمربوطهفعالاست = isMeasuringArea;
        else if (modeName === 'circle') وضعحالیمربوطهفعالاست = isMeasuringCircle;
        else if (modeName === 'calibrate') وضعحالیمربوطهفعالاست = isCalibrating;

        deactivateAllModes(); // Siempre desactivar todos los modos primero

        if (!وضعحالیمربوطهفعالاست) { // Si no estaba activo, activarlo
            activateFunction(); // Llama a la función que activa el modo (ej. activateMeasureDistanceMode)
                                // Esta función ya se encarga de poner .active y el texto activo.
        }
        // Si ESTABA activo, deactivateAllModes ya lo limpió (quitó .active y restauró texto por defecto).
        redrawAllScreenElements();
    });
}
// Textos para los botones (deben coincidir con el estado inactivo y activo deseado)
setupModeButton(measureDistanceBtn, activateMeasureDistanceMode, 'distance', 'Cancel. Dist.', 'Distancia');
setupModeButton(measureAreaBtn, activateMeasureAreaMode, 'area', 'Cancel. Área', 'Área');
setupModeButton(measureCircleBtn, activateMeasureCircleMode, 'circle', 'Cancel. Círculo', 'Círculo');
setupModeButton(startCalibrateBtn, activateCalibrationMode, 'calibrate', 'Cancel. Cal.', 'Calibrar');

// (Resto de listeners de botones: setScaleBtn, applyPredefinedScaleBtn, finishShapeBtn, clearMeasurementsBtn, zoom, paginación)
// ... estos se mantienen como en tu script completo ...
if (setScaleBtn && knownLengthInput && knownUnitSelect && calibrationStatusEl && currentScaleInfoEl) {
    setScaleBtn.addEventListener('click', () => {
        if (calibrationPoints.length === 2) {
            const knownLength = parseFloat(knownLengthInput.value);
            if (isNaN(knownLength) || knownLength <= 0) { alert("Longitud inválida."); return; }
            realWorldUnit = knownUnitSelect.value;
            const pdfDist = calculateDistance(calibrationPoints[0], calibrationPoints[1]);
            scaleFactor = knownLength / pdfDist;
            calibrationStatusEl.textContent = `Escala: 1 ${realWorldUnit} = ${(pdfDist / knownLength).toFixed(2)} unid.PDF`;
            currentScaleInfoEl.textContent = `${scaleFactor.toFixed(4)} ${realWorldUnit}/unid.PDF`;
            if (calibrationInputDiv) calibrationInputDiv.style.display = 'none';
            // No es necesario llamar a deactivateAllModes aquí porque isCalibrating se pone a false abajo
            // y el botón de calibración se resetea por setupModeButton si se hace clic de nuevo.
            isCalibrating = false; // Salir del modo calibración
            calibrationPoints = [];
            if (startCalibrateBtn) { // Restaurar botón de calibración
                startCalibrateBtn.classList.remove('active');
                startCalibrateBtn.textContent = 'Calibrar';
            }
            if (measureCanvas) measureCanvas.style.cursor = DEFAULT_CURSOR;
            redrawAllScreenElements();
        } else { alert("Selecciona dos puntos primero."); }
    });
}
// ... (resto de tus listeners de botones, igual que en el script que me pasaste)
if (applyPredefinedScaleBtn && predefinedScaleSelect && currentScaleInfoEl && calibrationStatusEl && knownUnitSelect) { applyPredefinedScaleBtn.addEventListener('click', () => { const selectedOption = predefinedScaleSelect.options[predefinedScaleSelect.selectedIndex]; const scaleValueInput = selectedOption.value; const sfFromData = selectedOption.dataset.scalefactor; const unitFromData = selectedOption.dataset.unit; if (!scaleValueInput && !sfFromData) { alert("Selecciona una escala."); return; } realWorldUnit = unitFromData || knownUnitSelect.value; scaleFactor = parseFloat(sfFromData || scaleValueInput); if (isNaN(scaleFactor) || scaleFactor <= 0) { alert("Factor de escala inválido."); return; } currentScaleInfoEl.textContent = `Escala: ${scaleFactor.toFixed(4)} ${realWorldUnit}/unid.PDF (1:${scaleFactor})`; calibrationStatusEl.textContent = `Escala predefinida aplicada.`; deactivateAllModes(); redrawAllScreenElements(); });}
if (finishShapeBtn) { finishShapeBtn.addEventListener('click', () => { if (isMeasuringArea && areaPoints.length >= 3) { const pdfArea = calculateAreaShoelace(areaPoints); const realWorld = convertToRealWorld(pdfArea, scaleFactor, realWorldUnit, true); allMeasurements.push({ type: 'area', pointsPdf: [...areaPoints], value: realWorld.value, unit: realWorld.unit, pageNum: currentPageNum }); areaPoints = []; updateMeasurementsList(); } else if (isMeasuringArea) { alert("Se necesitan al menos 3 puntos para un área."); } deactivateAllModes(); redrawAllScreenElements(); });}
if (clearMeasurementsBtn) { clearMeasurementsBtn.addEventListener('click', () => { if (confirm("¿Borrar todas las mediciones?")) { allMeasurements = []; currentlySelectedMeasurementIndex = -1; currentlySelectedPointIndex = -1; updateMeasurementsList(); redrawAllScreenElements(); } });}
if (zoomInBtn) { zoomInBtn.addEventListener('click', () => { currentRenderScale += ZOOM_FACTOR; queueRenderPage(currentPageNum); }); }
if (zoomOutBtn) { zoomOutBtn.addEventListener('click', () => { if (currentRenderScale - ZOOM_FACTOR >= 0.1) { currentRenderScale -= ZOOM_FACTOR; queueRenderPage(currentPageNum); } }); }
function updateZoomLevelInfo() { if (zoomLevelInfoEl) zoomLevelInfoEl.textContent = `${(currentRenderScale * 100).toFixed(0)}%`; }
if (pdfFileInput) { pdfFileInput.addEventListener('change', function(event) { const file = event.target.files[0]; if (file && file.type === 'application/pdf') { const fileURL = URL.createObjectURL(file); loadAndRenderPdf(fileURL); } else if (file) { alert('Selecciona un archivo PDF.'); pdfFileInput.value = ''; } });}
if (prevPageBtn) { prevPageBtn.addEventListener('click', () => { if (currentPageNum > 1) queueRenderPage(currentPageNum - 1); }); }
if (nextPageBtn) { nextPageBtn.addEventListener('click', () => { if (pdfDoc && currentPageNum < pdfDoc.numPages) queueRenderPage(currentPageNum + 1); }); }
if (goToPageBtn && goToPageInput) { goToPageBtn.addEventListener('click', () => { if (!pdfDoc) return; let page = parseInt(goToPageInput.value); if (!isNaN(page) && page >= 1 && page <= pdfDoc.numPages) { queueRenderPage(page); goToPageInput.value = ''; } else { alert(`Página entre 1 y ${pdfDoc.numPages}.`); goToPageInput.value = currentPageNum; } }); goToPageInput.addEventListener('keypress', function(event) { if (event.key === 'Enter') { event.preventDefault(); if (goToPageBtn) goToPageBtn.click(); } });}


// --- INICIALIZACIÓN DEL SCRIPT ---
// (Sin cambios aquí, se mantiene como en tu script completo)
document.addEventListener('DOMContentLoaded', () => {
    if (!canvas || !measureCanvas || !context || !measureContext) {
        console.error("Error crítico: Uno o más elementos canvas o sus contextos no se encontraron.");
        alert("Error al inicializar la herramienta de medición. Revisa la consola.");
        return;
    }
    resetApplicationState();
    updateZoomLevelInfo();
    updatePaginationControls();
    if(knownUnitSelect) realWorldUnit = knownUnitSelect.value;
    if (typeof PDF_URL_TO_LOAD !== 'undefined' && PDF_URL_TO_LOAD) {
        console.log("Cargando PDF desde URL (Flask):", PDF_URL_TO_LOAD);
        const pdfLoadSectionTop = document.getElementById('pdf-load-section-top');
        if(pdfLoadSectionTop) pdfLoadSectionTop.style.display = 'none';
        if(pdfLoadSection) pdfLoadSection.classList.add('file-input-hidden');
        loadAndRenderPdf(PDF_URL_TO_LOAD);
    } else {
        console.log("No se proporcionó PDF_URL_TO_LOAD. Esperando carga local.");
        const pdfLoadSectionTop = document.getElementById('pdf-load-section-top');
        if(pdfLoadSectionTop) pdfLoadSectionTop.style.display = 'block';
       else if(pdfLoadSection) pdfLoadSection.classList.remove('file-input-hidden');
    }
    console.log("Script de medición cargado y DOM listo.");
});
