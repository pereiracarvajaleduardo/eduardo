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
const CALIBRATION_POINT_COLOR = 'rgba(255, 0, 0, 0.7)';
const MEASUREMENT_POINT_COLOR = 'rgba(0, 0, 255, 0.7)';
const MEASUREMENT_LINE_COLOR = 'blue';
const AREA_POLYGON_COLOR_FILL = 'rgba(0, 128, 0, 0.3)';
const AREA_LINE_COLOR = 'green';
const CIRCLE_FILL_COLOR = 'rgba(255, 165, 0, 0.3)';
const CIRCLE_LINE_COLOR = 'orange';
const CANVAS_POINT_RADIUS_BASE = 3; // Reducido para más precisión visual
const TEXT_BG_COLOR_MEASUREMENTS = '#ffffffaa';
const TEXT_COLOR_MEASUREMENTS = '#000000';
const TEXT_FONT_MEASUREMENTS = '10px Arial';
const TEXT_PADDING_MEASUREMENTS = 2;


// --- ELEMENTOS DEL DOM ---
const pdfFileInput = document.getElementById('pdf-file-input');
const pdfLoadSection = document.getElementById('pdf-load-section');
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
let currentPdfSource = null; // Para revocar ObjectURLs

let isCalibrating = false;
let calibrationPoints = []; // {x, y} en coordenadas PDF
let scaleFactor = null; // factor para convertir unidades PDF a unidades reales (ej: mm por unidad PDF)
let realWorldUnit = 'mm'; // Unidad del mundo real (ej: mm, cm, m, in, ft)

let isMeasuringDistance = false;
let measurementPoints = []; // {x, y} en coordenadas PDF

let isMeasuringArea = false;
let areaPoints = []; // {x, y} en coordenadas PDF

let isMeasuringCircle = false;
let circlePoints = []; // {x, y} en coordenadas PDF, hasta 3 puntos

let allMeasurements = []; // Array de objetos: { type: 'distance'|'area'|'circle', pointsPdf: [], value: number, unit: string, pageNum: number, screenPoints?: [] }
let currentMousePosPdf = null; // Posición actual del mouse en coordenadas PDF para previsualizaciones

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
    // currentRenderScale = 1.5; // No resetear escala de zoom al cargar nuevo PDF

    scaleFactor = null;
    realWorldUnit = knownUnitSelect ? knownUnitSelect.value : 'mm';
    if(currentScaleInfoEl) currentScaleInfoEl.textContent = "No calibrada";
    if(calibrationStatusEl) calibrationStatusEl.textContent = 'Esperando inicio...';
    if(calibrationInputDiv) calibrationInputDiv.style.display = 'none';
    calibrationPoints = [];

    deactivateAllModes();

    measurementPoints = [];
    areaPoints = [];
    circlePoints = [];
    allMeasurements = [];

    clearMeasureCanvas();
    updateMeasurementsList();
    updateZoomLevelInfo();
    updatePaginationControls();

    if(measureCanvas) {
        measureCanvas.style.pointerEvents = 'none'; // Desactivar clics hasta que se cargue PDF
        measureCanvas.style.cursor = DEFAULT_CURSOR;
    }
    console.log('Estado de la aplicación reseteado.');
}

function loadAndRenderPdf(pdfSource) {
    if (!pdfSource) {
        console.warn("loadAndRenderPdf llamado sin fuente de PDF.");
        if(pdfLoadSection) pdfLoadSection.classList.remove('file-input-hidden');
        updatePaginationControls();
        return;
    }

    if (currentPdfSource && typeof currentPdfSource === 'string' && currentPdfSource.startsWith('blob:')) {
        URL.revokeObjectURL(currentPdfSource); // Limpiar URL de objeto anterior
    }
    currentPdfSource = pdfSource;

    resetApplicationState(); // Resetea todo, incluyendo la paginación y mediciones

    const loadingTask = pdfjsLib.getDocument(pdfSource);
    loadingTask.promise.then(function(pdfDoc_) {
        pdfDoc = pdfDoc_;
        console.log('PDF cargado:', pdfDoc.numPages, 'páginas.');
        currentPageNum = 1;
        if(measureCanvas) measureCanvas.style.pointerEvents = 'auto'; // Activar clics
        updatePaginationControls();
        queueRenderPage(currentPageNum);
        if(pdfLoadSection) pdfLoadSection.classList.add('file-input-hidden');
    }).catch(function(reason) {
        console.error('Error al cargar el PDF:', reason);
        alert('Error al cargar el PDF: ' + (reason.message || 'Error desconocido. Revisa la consola.'));
        resetApplicationState();
        if(pdfLoadSection) pdfLoadSection.classList.remove('file-input-hidden');
    });
}

// --- UTILIDADES DE COORDENADAS ---
function getPdfPoint(screenX, screenY) {
    if (!currentViewport) return null;
    const rect = measureCanvas.getBoundingClientRect();
    const canvasX = screenX - rect.left;
    const canvasY = screenY - rect.top;
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
    ctx.beginPath();
    ctx.arc(screenPoint.x, screenPoint.y, radius / currentRenderScale * 1.5, 0, 2 * Math.PI, false); // Radio ajustado al zoom
    ctx.fillStyle = color;
    ctx.fill();
    ctx.lineWidth = 1;
    ctx.strokeStyle = 'black';
    ctx.stroke();
}

function drawLine(ctx, screenP1, screenP2, color, lineWidth = 2) {
    if (!screenP1 || !screenP2) return;
    ctx.beginPath();
    ctx.moveTo(screenP1.x, screenP1.y);
    ctx.lineTo(screenP2.x, screenP2.y);
    ctx.strokeStyle = color;
    ctx.lineWidth = lineWidth / currentRenderScale * 1.5; // Grosor ajustado al zoom
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
    const offsetY = options.offsetY || -5; // Desplazar texto un poco arriba del punto/línea

    ctx.font = font;
    ctx.textAlign = textAlign;
    ctx.textBaseline = textBaseline;

    const textWidth = ctx.measureText(text).width;
    const textHeight = parseInt(font, 10); // Aproximación de la altura

    const bgX = screenPoint.x - (textAlign === 'center' ? textWidth / 2 : 0) - padding;
    const bgY = screenPoint.y + offsetY - textHeight - padding;
    const bgWidth = textWidth + 2 * padding;
    const bgHeight = textHeight + 2 * padding;

    ctx.fillStyle = bgColor;
    ctx.fillRect(bgX, bgY, bgWidth, bgHeight);

    ctx.fillStyle = textColor;
    ctx.fillText(text, screenPoint.x, screenPoint.y + offsetY);
}


function redrawAllScreenElements() {
    if (!measureContext || !currentViewport) return;
    clearMeasureCanvas();

    // 1. Dibujar puntos de calibración en curso
    if (isCalibrating && calibrationPoints.length > 0) {
        const screenCalPoints = getScreenPoints(calibrationPoints);
        screenCalPoints.forEach(p => drawPoint(measureContext, p, CALIBRATION_POINT_COLOR));
        if (screenCalPoints.length === 1 && currentMousePosPdf) {
            drawLine(measureContext, screenCalPoints[0], getScreenPoint(currentMousePosPdf), CALIBRATION_POINT_COLOR, 1);
        }
    }

    // 2. Dibujar mediciones completadas para la página actual
    allMeasurements.forEach(m => {
        if (m.pageNum !== currentPageNum) return; // Solo dibujar mediciones de la página actual

        const screenPoints = getScreenPoints(m.pointsPdf);
        m.screenPoints = screenPoints; // Guardar para interacciones futuras si es necesario

        if (m.type === 'distance' && screenPoints.length === 2) {
            drawLine(measureContext, screenPoints[0], screenPoints[1], MEASUREMENT_LINE_COLOR);
            screenPoints.forEach(p => drawPoint(measureContext, p, MEASUREMENT_POINT_COLOR));
            const midPoint = { x: (screenPoints[0].x + screenPoints[1].x) / 2, y: (screenPoints[0].y + screenPoints[1].y) / 2 };
            drawMeasurementTextWithBackground(measureContext, `${m.value.toFixed(2)} ${m.unit}`, midPoint);
        } else if (m.type === 'area' && screenPoints.length > 2) {
            drawPolygon(measureContext, screenPoints, AREA_LINE_COLOR, AREA_POLYGON_COLOR_FILL);
            screenPoints.forEach(p => drawPoint(measureContext, p, MEASUREMENT_POINT_COLOR));
            // Calcular un centroide aproximado para el texto
            let centerX = 0, centerY = 0;
            screenPoints.forEach(p => { centerX += p.x; centerY += p.y; });
            const center = { x: centerX / screenPoints.length, y: centerY / screenPoints.length };
            drawMeasurementTextWithBackground(measureContext, `${m.value.toFixed(2)} ${m.unit}\u00B2`, center); // \u00B2 es ²
        } else if (m.type === 'circle' && m.centerPdf && typeof m.radiusPdf !== 'undefined') {
            const screenCenter = getScreenPoint(m.centerPdf);
            const screenRadius = m.radiusPdf * (currentViewport.scale / (m.originalScaleAtMeasurement || currentViewport.scale)); // Ajustar radio visual al zoom
            if (screenCenter && screenRadius > 0) {
                 drawCircle(measureContext, screenCenter, screenRadius, CIRCLE_LINE_COLOR, CIRCLE_FILL_COLOR);
                 m.pointsPdf.forEach(p => drawPoint(measureContext, getScreenPoint(p), MEASUREMENT_POINT_COLOR)); // Puntos originales
                 drawMeasurementTextWithBackground(measureContext, `R: ${m.radiusDisplay.toFixed(2)} ${m.unit}\nA: ${m.value.toFixed(2)} ${m.unit}\u00B2`, screenCenter);
            }
        }
    });

    // 3. Dibujar medición en curso
    if (isMeasuringDistance) {
        const screenMeasurementPoints = getScreenPoints(measurementPoints);
        screenMeasurementPoints.forEach(p => drawPoint(measureContext, p, MEASUREMENT_POINT_COLOR));
        if (screenMeasurementPoints.length === 1 && currentMousePosPdf) {
            drawLine(measureContext, screenMeasurementPoints[0], getScreenPoint(currentMousePosPdf), MEASUREMENT_LINE_COLOR, 1);
        }
    } else if (isMeasuringArea) {
        const screenAreaPoints = getScreenPoints(areaPoints);
        screenAreaPoints.forEach(p => drawPoint(measureContext, p, MEASUREMENT_POINT_COLOR));
        if (screenAreaPoints.length > 0 && currentMousePosPdf) {
            const tempPoints = [...screenAreaPoints, getScreenPoint(currentMousePosPdf)];
            drawPolygon(measureContext, tempPoints, AREA_LINE_COLOR, AREA_POLYGON_COLOR_FILL, 1, areaPoints.length >=2);
        }
    } else if (isMeasuringCircle) {
        const screenCirclePoints = getScreenPoints(circlePoints);
        screenCirclePoints.forEach(p => drawPoint(measureContext, p, MEASUREMENT_POINT_COLOR));
        if (screenCirclePoints.length === 1 && currentMousePosPdf) {
            drawLine(measureContext, screenCirclePoints[0], getScreenPoint(currentMousePosPdf), CIRCLE_LINE_COLOR, 1);
        } else if (screenCirclePoints.length === 2 && currentMousePosPdf) {
             // Previsualizar círculo con 3 puntos
            const tempPdfPoints = [...circlePoints, currentMousePosPdf];
            const circleParams = calculateCircleFrom3Points(tempPdfPoints[0], tempPdfPoints[1], tempPdfPoints[2]);
            if (circleParams) {
                const screenCenter = getScreenPoint(circleParams.centerPdf);
                // El radio en PDF debe convertirse a radio en pantalla
                // Un segmento horizontal de longitud radiusPdf en PDF
                const p1 = { x: circleParams.centerPdf.x, y: circleParams.centerPdf.y };
                const p2 = { x: circleParams.centerPdf.x + circleParams.radiusPdf, y: circleParams.centerPdf.y };
                const sp1 = getScreenPoint(p1);
                const sp2 = getScreenPoint(p2);
                const screenRadius = Math.sqrt(Math.pow(sp2.x - sp1.x, 2) + Math.pow(sp2.y - sp1.y, 2));

                if (screenCenter && screenRadius > 0) {
                    drawCircle(measureContext, screenCenter, screenRadius, CIRCLE_LINE_COLOR, CIRCLE_FILL_COLOR, 1);
                }
            }
        }
    }
}


function updateMeasurementsList() {
    if (!measurementsListEl) return;
    measurementsListEl.innerHTML = ''; // Limpiar lista
    allMeasurements.forEach((m, index) => {
        const listItem = document.createElement('li');
        let text = `Medición ${index + 1} (Pág. ${m.pageNum}): `;
        if (m.type === 'distance') {
            text += `Distancia = ${m.value.toFixed(2)} ${m.unit}`;
        } else if (m.type === 'area') {
            text += `Área = ${m.value.toFixed(2)} ${m.unit}\u00B2`;
        } else if (m.type === 'circle') {
            text += `Círculo - Radio: ${m.radiusDisplay.toFixed(2)} ${m.unit}, Área: ${m.value.toFixed(2)} ${m.unit}\u00B2`;
        }
        listItem.textContent = text;
        measurementsListEl.appendChild(listItem);
    });
}

// --- MANEJO DE MODOS ---
function deactivateAllModes() {
    isCalibrating = false;
    isMeasuringDistance = false;
    isMeasuringArea = false;
    isMeasuringCircle = false;

    calibrationPoints = [];
    measurementPoints = [];
    areaPoints = [];
    circlePoints = [];

    if (measureStatusEl) measureStatusEl.textContent = 'Selecciona una herramienta para comenzar.';
    if (measureDistanceBtn) measureDistanceBtn.textContent = 'Medir Distancia';
    if (measureAreaBtn) measureAreaBtn.textContent = 'Medir Área';
    if (measureCircleBtn) measureCircleBtn.textContent = 'Medir Círculo';
    if (startCalibrateBtn) startCalibrateBtn.textContent = 'Iniciar Calibración';
    if (finishShapeBtn) finishShapeBtn.style.display = 'none';
    if (measureCanvas) measureCanvas.style.cursor = DEFAULT_CURSOR;

    redrawAllScreenElements();
}

function activateCalibrationMode() {
    deactivateAllModes();
    isCalibrating = true;
    if (measureStatusEl) measureStatusEl.textContent = 'Calibración: Haz clic en dos puntos de una distancia conocida.';
    if (startCalibrateBtn) startCalibrateBtn.textContent = 'Cancel. Calibración';
    if (calibrationInputDiv) calibrationInputDiv.style.display = 'none'; // Ocultar hasta tener 2 puntos
    if (measureCanvas) measureCanvas.style.cursor = PRECISE_CURSOR;
}

function activateMeasureDistanceMode() {
    if (!scaleFactor) {
        alert("Por favor, calibra la escala primero o selecciona una escala predefinida.");
        return;
    }
    deactivateAllModes();
    isMeasuringDistance = true;
    if (measureStatusEl) measureStatusEl.textContent = 'Mid. Distancia: Haz clic en dos puntos.';
    if (measureDistanceBtn) measureDistanceBtn.textContent = 'Cancel. Distancia';
    if (measureCanvas) measureCanvas.style.cursor = PRECISE_CURSOR;
}

function activateMeasureAreaMode() {
    if (!scaleFactor) {
        alert("Por favor, calibra la escala primero o selecciona una escala predefinida.");
        return;
    }
    deactivateAllModes();
    isMeasuringArea = true;
    if (measureStatusEl) measureStatusEl.textContent = 'Mid. Área: Haz clic para agregar puntos. Mínimo 3.';
    if (measureAreaBtn) measureAreaBtn.textContent = 'Cancel. Área';
    if (finishShapeBtn) finishShapeBtn.style.display = 'inline-block';
    if (measureCanvas) measureCanvas.style.cursor = PRECISE_CURSOR;
}

function activateMeasureCircleMode() {
    if (!scaleFactor) {
        alert("Por favor, calibra la escala primero o selecciona una escala predefinida.");
        return;
    }
    deactivateAllModes();
    isMeasuringCircle = true;
    if (measureStatusEl) measureStatusEl.textContent = 'Mid. Círculo: Haz clic en 3 puntos en la circunferencia.';
    if (measureCircleBtn) measureCircleBtn.textContent = 'Cancel. Círculo';
    if (measureCanvas) measureCanvas.style.cursor = PRECISE_CURSOR;
}

// --- CÁLCULOS GEOMÉTRICOS ---
function calculateDistance(pdfP1, pdfP2) {
    return Math.sqrt(Math.pow(pdfP2.x - pdfP1.x, 2) + Math.pow(pdfP2.y - pdfP1.y, 2));
}

function convertToRealWorld(pdfValue, sf, unit, isArea = false) {
    if (!sf) return { value: pdfValue, unit: 'unidades PDF' + (isArea ? '²' : '') };
    const conversionFactor = isArea ? sf * sf : sf;
    return { value: pdfValue * conversionFactor, unit: unit };
}

// Algoritmo Shoelace para área de polígono
function calculateAreaShoelace(pdfPoints) {
    let area = 0;
    const n = pdfPoints.length;
    for (let i = 0; i < n; i++) {
        const p1 = pdfPoints[i];
        const p2 = pdfPoints[(i + 1) % n]; // Siguiente punto, ciclando al primero
        area += (p1.x * p2.y) - (p2.x * p1.y);
    }
    return Math.abs(area / 2);
}

// Calcular círculo a partir de 3 puntos (centro y radio en coords PDF)
function calculateCircleFrom3Points(p1, p2, p3) {
    const D = 2 * (p1.x * (p2.y - p3.y) + p2.x * (p3.y - p1.y) + p3.x * (p1.y - p2.y));
    if (Math.abs(D) < 1e-8) return null; // Puntos colineales

    const p1sq = p1.x * p1.x + p1.y * p1.y;
    const p2sq = p2.x * p2.x + p2.y * p2.y;
    const p3sq = p3.x * p3.x + p3.y * p3.y;

    const centerX = (p1sq * (p2.y - p3.y) + p2sq * (p3.y - p1.y) + p3sq * (p1.y - p2.y)) / D;
    const centerY = (p1sq * (p3.x - p2.x) + p2sq * (p1.x - p3.x) + p3sq * (p2.x - p1.x)) / D;
    const radius = calculateDistance({x: centerX, y: centerY}, p1);

    return { centerPdf: { x: centerX, y: centerY }, radiusPdf: radius };
}

// --- MANEJADORES DE EVENTOS ---
if (measureCanvas) {
    measureCanvas.addEventListener('mousemove', (event) => {
        if (!pdfDoc || !currentViewport) return;
        const rect = measureCanvas.getBoundingClientRect();
        const x = event.clientX - rect.left;
        const y = event.clientY - rect.top;

        if (screenCoordsEl) screenCoordsEl.textContent = `Pantalla: ${x.toFixed(0)}, ${y.toFixed(0)}`;
        const pdfPoint = currentViewport.convertToPdfPoint(x, y);
        if (pdfCoordsEl) pdfCoordsEl.textContent = `PDF: ${pdfPoint[0].toFixed(2)}, ${pdfPoint[1].toFixed(2)}`;
        
        currentMousePosPdf = {x: pdfPoint[0], y: pdfPoint[1]};

        if (isMeasuringDistance && measurementPoints.length === 1 ||
            isMeasuringArea && areaPoints.length > 0 ||
            isCalibrating && calibrationPoints.length === 1 ||
            isMeasuringCircle && (circlePoints.length === 1 || circlePoints.length === 2) ) {
            redrawAllScreenElements(); // Redibujar para mostrar línea/polígono/círculo temporal al cursor
        }
    });

    measureCanvas.addEventListener('click', (event) => {
        if (!pdfDoc || !currentViewport) return;
        const rect = measureCanvas.getBoundingClientRect();
        const x = event.clientX - rect.left;
        const y = event.clientY - rect.top;
        const pdfClickPoint = getPdfPoint(event.clientX, event.clientY); // Usar clientX/Y para getPdfPoint

        if (!pdfClickPoint) return;

        if (isCalibrating) {
            calibrationPoints.push(pdfClickPoint);
            if (calibrationPoints.length === 2) {
                if (calibrationInputDiv) calibrationInputDiv.style.display = 'block';
                if (measureStatusEl) measureStatusEl.textContent = 'Calibración: Ingresa la longitud conocida y unidad, luego presiona "Establecer Escala".';
            }
        } else if (isMeasuringDistance) {
            measurementPoints.push(pdfClickPoint);
            if (measurementPoints.length === 2) {
                const pdfDist = calculateDistance(measurementPoints[0], measurementPoints[1]);
                const realWorld = convertToRealWorld(pdfDist, scaleFactor, realWorldUnit);
                allMeasurements.push({
                    type: 'distance',
                    pointsPdf: [...measurementPoints],
                    value: realWorld.value,
                    unit: realWorld.unit,
                    pageNum: currentPageNum
                });
                deactivateAllModes(); // Opcional: o permitir múltiples mediciones
                updateMeasurementsList();
            }
        } else if (isMeasuringArea) {
            areaPoints.push(pdfClickPoint);
            if (areaPoints.length >= 3 && measureStatusEl) {
                 measureStatusEl.textContent = 'Mid. Área: Agrega más puntos o presiona "Terminar Forma".';
            }
        } else if (isMeasuringCircle) {
            circlePoints.push(pdfClickPoint);
             if (circlePoints.length === 3) {
                const circleParams = calculateCircleFrom3Points(circlePoints[0], circlePoints[1], circlePoints[2]);
                if (circleParams) {
                    const realWorldRadius = convertToRealWorld(circleParams.radiusPdf, scaleFactor, realWorldUnit);
                    const realWorldArea = convertToRealWorld(Math.PI * Math.pow(circleParams.radiusPdf, 2), scaleFactor, realWorldUnit, true);
                    
                    allMeasurements.push({
                        type: 'circle',
                        pointsPdf: [...circlePoints],
                        centerPdf: circleParams.centerPdf,
                        radiusPdf: circleParams.radiusPdf,
                        radiusDisplay: realWorldRadius.value, // Radio en unidades reales
                        value: realWorldArea.value, // Área en unidades reales
                        unit: realWorldRadius.unit, // Unidad base para radio y área (se añade ² para área en la lista)
                        pageNum: currentPageNum,
                        originalScaleAtMeasurement: currentViewport.scale // Guardar escala para redibujar círculo correctamente
                    });
                    deactivateAllModes();
                    updateMeasurementsList();
                } else {
                    alert("No se pudo calcular el círculo. Los puntos podrían ser colineales. Intenta de nuevo.");
                    circlePoints = []; // Resetear puntos para este intento
                }
            }
        }
        redrawAllScreenElements();
    });
}

// Botones de Herramientas
if (startCalibrateBtn) {
    startCalibrateBtn.addEventListener('click', () => {
        if (isCalibrating) deactivateAllModes();
        else activateCalibrationMode();
    });
}

if (setScaleBtn && knownLengthInput && knownUnitSelect && calibrationStatusEl && currentScaleInfoEl) {
    setScaleBtn.addEventListener('click', () => {
        if (calibrationPoints.length === 2) {
            const knownLength = parseFloat(knownLengthInput.value);
            if (isNaN(knownLength) || knownLength <= 0) {
                alert("Por favor, ingresa una longitud conocida válida.");
                return;
            }
            realWorldUnit = knownUnitSelect.value;
            const pdfDist = calculateDistance(calibrationPoints[0], calibrationPoints[1]);
            scaleFactor = knownLength / pdfDist; // Unidades reales por unidad PDF
            
            calibrationStatusEl.textContent = `Escala establecida: 1 unidad PDF = ${(1 / scaleFactor).toFixed(4)} ${realWorldUnit} (o 1 ${realWorldUnit} = ${scaleFactor.toFixed(4)} unidades PDF)`;
            currentScaleInfoEl.textContent = `Escala: ${scaleFactor.toFixed(4)} ${realWorldUnit}/unidad PDF`;
            if (calibrationInputDiv) calibrationInputDiv.style.display = 'none';
            // deactivateAllModes(); // Mantiene la calibración activa para referencia visual o la desactiva
            isCalibrating = false; // Terminar modo calibración
            calibrationPoints = []; // Limpiar puntos de calibración
            if (startCalibrateBtn) startCalibrateBtn.textContent = 'Iniciar Calibración';
            if (measureCanvas) measureCanvas.style.cursor = DEFAULT_CURSOR;
            redrawAllScreenElements(); // Limpiar puntos de calibración de la pantalla
        } else {
            alert("Por favor, selecciona dos puntos en el PDF primero.");
        }
    });
}

if (applyPredefinedScaleBtn && predefinedScaleSelect && currentScaleInfoEl && calibrationStatusEl) {
    applyPredefinedScaleBtn.addEventListener('click', () => {
        const selected = predefinedScaleSelect.value;
        if (!selected) {
            alert("Por favor, selecciona una escala predefinida.");
            return;
        }
        const parts = selected.split(':'); // ej "1:100" -> sf_input = 100, unit_input = 'mm' (asumido)
                                        // ej "1/4in=1ft" -> 0.25in = 12in -> sf = 12/0.25 = 48 (si la unidad PDF es pulgadas)
                                        // Esto necesita una lógica de parseo más robusta o valores directos de scaleFactor
        
        // Simplificación: Asumimos que el valor es directamente el scaleFactor (ej: PDF es 1:1 y la unidad es mm, el scale factor es 1)
        // O si el PDF está en una escala (ej. 1:100), 1 unidad PDF = 100 mm. Entonces scaleFactor = 100.
        // Para este ejemplo, si el select tiene "100 (mm por unidad PDF)", value="100"
        // Si tienes formatos como "1:100 (mm)", necesitas parsearlo.
        
        // Ejemplo de valor directo: <option value="100">Escala 1:100 (1 unidad PDF = 100mm)</option>
        //                       <option value="25.4">Escala Dibujo en Pulgadas (1 unidad PDF = 25.4mm)</option>
        const sfValue = parseFloat(predefinedScaleSelect.options[predefinedScaleSelect.selectedIndex].dataset.scalefactor);
        const unitValue = predefinedScaleSelect.options[predefinedScaleSelect.selectedIndex].dataset.unit || 'mm';

        if (isNaN(sfValue) || sfValue <= 0) {
             alert("La escala predefinida no tiene un factor de escala válido.");
             return;
        }

        scaleFactor = sfValue;
        realWorldUnit = unitValue;

        currentScaleInfoEl.textContent = `Escala: ${scaleFactor.toFixed(4)} ${realWorldUnit}/unidad PDF`;
        calibrationStatusEl.textContent = `Escala predefinida aplicada.`;
        deactivateAllModes(); // Limpiar cualquier modo activo
    });
}


if (measureDistanceBtn) {
    measureDistanceBtn.addEventListener('click', () => {
        if (isMeasuringDistance) deactivateAllModes();
        else activateMeasureDistanceMode();
    });
}
if (measureAreaBtn) {
    measureAreaBtn.addEventListener('click', () => {
        if (isMeasuringArea) deactivateAllModes();
        else activateMeasureAreaMode();
    });
}
if (measureCircleBtn) {
    measureCircleBtn.addEventListener('click', () => {
        if (isMeasuringCircle) deactivateAllModes();
        else activateMeasureCircleMode();
    });
}

if (finishShapeBtn) {
    finishShapeBtn.addEventListener('click', () => {
        if (isMeasuringArea && areaPoints.length >= 3) {
            const pdfArea = calculateAreaShoelace(areaPoints);
            const realWorld = convertToRealWorld(pdfArea, scaleFactor, realWorldUnit, true);
            allMeasurements.push({
                type: 'area',
                pointsPdf: [...areaPoints],
                value: realWorld.value,
                unit: realWorld.unit,
                pageNum: currentPageNum
            });
            deactivateAllModes();
            updateMeasurementsList();
            redrawAllScreenElements();
        } else if (isMeasuringArea) {
            alert("Necesitas al menos 3 puntos para definir un área.");
        } else {
             // Podría usarse para otras formas en el futuro
            deactivateAllModes();
        }
    });
}


if (clearMeasurementsBtn) {
    clearMeasurementsBtn.addEventListener('click', () => {
        if (confirm("¿Estás seguro de que quieres borrar todas las mediciones?")) {
            allMeasurements = [];
            updateMeasurementsList();
            redrawAllScreenElements();
        }
    });
}

// Zoom
if (zoomInBtn) {
    zoomInBtn.addEventListener('click', () => {
        currentRenderScale += ZOOM_FACTOR;
        queueRenderPage(currentPageNum);
    });
}
if (zoomOutBtn) {
    zoomOutBtn.addEventListener('click', () => {
        if (currentRenderScale - ZOOM_FACTOR >= ZOOM_FACTOR) { // Evitar zoom demasiado pequeño
            currentRenderScale -= ZOOM_FACTOR;
            queueRenderPage(currentPageNum);
        }
    });
}
function updateZoomLevelInfo() {
    if (zoomLevelInfoEl) {
        zoomLevelInfoEl.textContent = `${(currentRenderScale * 100).toFixed(0)}%`;
    }
}


// Paginación (ya definidos en la primera parte, solo los listeners)
if (pdfFileInput) {
    pdfFileInput.addEventListener('change', function(event) {
        const file = event.target.files[0];
        if (file && file.type === 'application/pdf') {
            const fileURL = URL.createObjectURL(file);
            loadAndRenderPdf(fileURL); // loadAndRenderPdf se encargará de revocarla
        } else if (file) {
            alert('Por favor, selecciona un archivo PDF.');
            pdfFileInput.value = ''; // Resetear input si no es PDF
        }
    });
}

if (prevPageBtn) {
    prevPageBtn.addEventListener('click', () => {
        if (currentPageNum > 1) queueRenderPage(currentPageNum - 1);
    });
}
if (nextPageBtn) {
    nextPageBtn.addEventListener('click', () => {
        if (pdfDoc && currentPageNum < pdfDoc.numPages) queueRenderPage(currentPageNum + 1);
    });
}
if (goToPageBtn && goToPageInput) {
    goToPageBtn.addEventListener('click', () => {
        if (!pdfDoc) return;
        let page = parseInt(goToPageInput.value);
        if (!isNaN(page) && page >= 1 && page <= pdfDoc.numPages) {
            queueRenderPage(page);
            goToPageInput.value = '';
        } else {
            alert(`Por favor, ingresa un número de página entre 1 y ${pdfDoc.numPages}.`);
            goToPageInput.value = currentPageNum;
        }
    });
    goToPageInput.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            if (goToPageBtn) goToPageBtn.click();
        }
    });
}

// --- INICIALIZACIÓN DEL SCRIPT ---
document.addEventListener('DOMContentLoaded', () => {
    if (!canvas || !measureCanvas || !context || !measureContext) {
        console.error("Error crítico: Uno o más elementos canvas o sus contextos no se encontraron.");
        alert("Error al inicializar la herramienta de medición. Revisa la consola.");
        return;
    }
    
    resetApplicationState(); // Estado inicial limpio
    updateZoomLevelInfo();
    updatePaginationControls();

    // Configurar unidades y escalas predefinidas
    if(knownUnitSelect) realWorldUnit = knownUnitSelect.value;
    // Aquí podrías popular `predefinedScaleSelect` dinámicamente si es necesario
    // Ejemplo: <option value="data-scalefactor_value" data-unit="unit_value">Display Text</option>

    if (typeof PDF_URL_TO_LOAD !== 'undefined' && PDF_URL_TO_LOAD) {
        console.log("Cargando PDF desde URL (Flask):", PDF_URL_TO_LOAD);
        if (pdfLoadSection) pdfLoadSection.classList.add('file-input-hidden');
        loadAndRenderPdf(PDF_URL_TO_LOAD);
    } else {
        console.log("No se proporcionó PDF_URL_TO_LOAD. Esperando carga local.");
        if (pdfLoadSection) pdfLoadSection.classList.remove('file-input-hidden');
    }
    console.log("Script de medición cargado y DOM listo.");
});