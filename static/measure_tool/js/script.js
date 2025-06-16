// static/measure_tool/js/script.js --- VERSIÓN FINAL CON TODAS LAS FUNCIONES

// --- 1. CONFIGURACIÓN E IMPORTACIÓN ---
import * as pdfjsLib from '/static/lib/pdfjs/build/pdf.mjs';

if (typeof pdfjsLib !== 'undefined' && typeof PDF_WORKER_URL !== 'undefined' && PDF_WORKER_URL) {
    pdfjsLib.GlobalWorkerOptions.workerSrc = PDF_WORKER_URL;
} else {
    console.error("FATAL: PDF.js o su worker no están configurados correctamente.");
    alert("Error crítico al cargar el visor de PDF. Revisa la consola (F12).");
}

// --- 2. CONSTANTES DE CONFIGURACIÓN ---
const RENDER_SCALE_INITIAL = 1.0;
const ZOOM_FACTOR = 0.25;
const GRID_COLOR = 'rgba(128, 128, 128, 0.5)';
const DEFAULT_CURSOR = 'default';
const PRECISE_CURSOR = 'crosshair';
const GRABBING_CURSOR = 'grabbing';
const POINT_RADIUS = 4;
const DRAG_HANDLE_RADIUS = 8;
const TEXT_BG_COLOR = 'rgba(255, 255, 255, 0.8)';
const TEXT_COLOR = '#000000';
const TEXT_FONT = '12px Arial';
const LINE_COLOR_MEASURE = 'blue';
const LINE_COLOR_SELECTED = 'purple';
const FILL_COLOR_AREA = 'rgba(0, 128, 0, 0.3)';
const LINE_COLOR_AREA = 'green';
const POINT_COLOR_CALIBRATE = 'rgba(255, 0, 0, 0.7)';

// --- 3. ELEMENTOS DEL DOM ---
const loadedPdfNameEl = document.getElementById('loaded-pdf-name');
const canvas = document.getElementById('pdf-canvas');
const context = canvas.getContext('2d');
const measureCanvas = document.getElementById('measure-canvas');
const measureContext = measureCanvas.getContext('2d');
const startCalibrateBtn = document.getElementById('start-calibrate-btn');
const measureDistanceBtn = document.getElementById('measure-distance-btn');
const measureAreaBtn = document.getElementById('measure-area-btn');
const finishShapeBtn = document.getElementById('finish-shape-btn');
const zoomInBtn = document.getElementById('zoom-in-btn');
const zoomOutBtn = document.getElementById('zoom-out-btn');
const prevPageBtn = document.getElementById('prev-page-btn');
const nextPageBtn = document.getElementById('next-page-btn');
const goToPageInput = document.getElementById('go-to-page-input');
const goToPageBtn = document.getElementById('go-to-page-btn');
const calibrationInputDiv = document.getElementById('calibration-input-div');
const knownLengthInput = document.getElementById('known-length');
const setScaleBtn = document.getElementById('set-scale-btn');
const predefinedScaleSelect = document.getElementById('predefined-scale');
const applyPredefinedScaleBtn = document.getElementById('apply-predefined-scale-btn');
const knownUnitSelect = document.getElementById('known-unit');
const currentScaleInfoEl = document.getElementById('current-scale-info');
const zoomLevelInfoEl = document.getElementById('zoom-level-info');
const pageNumEl = document.getElementById('page-num');
const pageCountEl = document.getElementById('page-count');
const measurementsListEl = document.getElementById('measurements-list');
const clearMeasurementsBtn = document.getElementById('clear-measurements-btn');
const resetScaleBtn = document.getElementById('reset-scale-btn');
const pageSizeInfoEl = document.getElementById('page-size-info');
const toggleGridBtn = document.getElementById('toggle-grid-btn');
const gridControlsDiv = document.getElementById('grid-controls');
const gridSpacingInput = document.getElementById('grid-spacing-input');
const gridUnitSelect = document.getElementById('grid-unit-select');

// --- 4. ESTADO GLOBAL DE LA APLICACIÓN ---
let pdfDoc = null;
let currentPageNum = 1;
let currentRenderScale = RENDER_SCALE_INITIAL;
let pageRendering = false;
let pageNumPending = null;
let currentViewport = null;
let currentMousePosPdf = null;
let scaleFactor = null;
let realWorldUnit = 'mm';
let currentTool = 'none';
let currentPoints = [];
let allMeasurements = [];
let selectedMeasurementIndex = -1;
let selectedPointIndex = -1;
let isDraggingPoint = false;
let gridEnabled = false;

// --- 5. FUNCIONES PRINCIPALES Y DE LÓGICA ---

function loadAndRenderPdf(pdfSource) {
    resetApplicationState();
    const loadingTask = pdfjsLib.getDocument(pdfSource);
    loadingTask.promise.then(pdfDoc_ => {
        pdfDoc = pdfDoc_;
        if(pageCountEl) pageCountEl.textContent = pdfDoc.numPages;
        renderPage(1);
    }).catch(err => {
        console.error("Error al cargar el PDF:", err);
        alert("No se pudo cargar el archivo PDF.");
    });
}

function renderPage(num) {
    if (pageRendering) {
        pageNumPending = num;
        return;
    }
    pageRendering = true;
    currentPageNum = num;
    if(pageNumEl) pageNumEl.textContent = num;

    pdfDoc.getPage(num).then(page => {
        currentViewport = page.getViewport({ scale: currentRenderScale });
        
        if (pageSizeInfoEl) {
            const pageWidthInPoints = page.view[2] - page.view[0];
            const pageHeightInPoints = page.view[3] - page.view[1];
            const mmPerPoint = 25.4 / 72;
            const pageWidthInMm = pageWidthInPoints * mmPerPoint;
            const pageHeightInMm = pageHeightInPoints * mmPerPoint;
            const paperSizeName = getPaperSizeName(pageWidthInMm, pageHeightInMm);
            pageSizeInfoEl.textContent = `${pageWidthInMm.toFixed(1)} x ${pageHeightInMm.toFixed(1)} mm (${paperSizeName})`;
        }
        
        canvas.height = measureCanvas.height = currentViewport.height;
        canvas.width = measureCanvas.width = currentViewport.width;
        canvas.style.height = measureCanvas.style.height = `${currentViewport.height}px`;
        canvas.style.width = measureCanvas.style.width = `${currentViewport.width}px`;
        
        const renderContext = { canvasContext: context, viewport: currentViewport };
        page.render(renderContext).promise.then(() => {
            pageRendering = false;
            if (pageNumPending !== null) {
                renderPage(pageNumPending);
                pageNumPending = null;
            }
            redrawAllElements();
            if(zoomLevelInfoEl) zoomLevelInfoEl.textContent = `${(currentRenderScale * 100).toFixed(0)}%`;
        });
    }).catch(err => {
        console.error("Error al renderizar la página:", err);
        pageRendering = false;
    });
}

function getPaperSizeName(width, height) {
    const w = Math.min(width, height);
    const h = Math.max(width, height);
    const tolerance = 5;
    const isCloseTo = (val, target) => Math.abs(val - target) < tolerance;
    if (isCloseTo(w, 841) && isCloseTo(h, 1189)) return "A0";
    if (isCloseTo(w, 594) && isCloseTo(h, 841)) return "A1";
    if (isCloseTo(w, 420) && isCloseTo(h, 594)) return "A2";
    if (isCloseTo(w, 297) && isCloseTo(h, 420)) return "A3";
    if (isCloseTo(w, 210) && isCloseTo(h, 297)) return "A4";
    return "Personalizado";
}

function setActiveTool(toolName) {
    if (currentTool === toolName) toolName = 'none'; 
    if (toolName !== 'none' && toolName !== 'calibrate' && !scaleFactor) {
        showTemporaryMessage("Por favor, calibra la escala primero.", 'warning');
        return; 
    }
    currentTool = toolName;
    currentPoints = [];
    selectedMeasurementIndex = -1;
    if (calibrationInputDiv) calibrationInputDiv.style.display = 'none';
    updateUI();
}

function updateUI() {
    [measureDistanceBtn, measureAreaBtn, startCalibrateBtn].forEach(btn => btn && btn.classList.remove('active'));
    if (finishShapeBtn) finishShapeBtn.style.display = 'none';
    if(measureCanvas) measureCanvas.style.cursor = isDraggingPoint ? GRABBING_CURSOR : DEFAULT_CURSOR;
    switch (currentTool) {
        case 'calibrate': startCalibrateBtn?.classList.add('active'); if(measureCanvas) measureCanvas.style.cursor = PRECISE_CURSOR; break;
        case 'distance': measureDistanceBtn?.classList.add('active'); if(measureCanvas) measureCanvas.style.cursor = PRECISE_CURSOR; break;
        case 'area':
            measureAreaBtn?.classList.add('active');
            if (finishShapeBtn) finishShapeBtn.style.display = 'inline-block';
            if(measureCanvas) measureCanvas.style.cursor = PRECISE_CURSOR;
            break;
    }
    redrawAllElements();
}

function redrawAllElements() {
    if (!measureContext) return;
    measureContext.clearRect(0, 0, measureCanvas.width, measureCanvas.height);
    if (gridEnabled && scaleFactor) {
        drawGrid();
    }
    allMeasurements.forEach((m, index) => {
        if (m.pageNum !== currentPageNum) return;
        drawMeasurement(m, index === selectedMeasurementIndex);
    });
    if (currentPoints.length > 0) {
        drawInProgress();
    }
}

function drawGrid() {
    const canvasWidth = measureCanvas.width;
    const canvasHeight = measureCanvas.height;
    let spacingInRealUnits = parseFloat(gridSpacingInput.value) || 1;
    const spacingUnit = gridUnitSelect.value;
    let spacingInMm = spacingInRealUnits;
    switch(spacingUnit) {
        case 'm': spacingInMm *= 1000; break;
        case 'cm': spacingInMm *= 10; break;
    }
    let convertedSpacing = spacingInMm;
    switch(realWorldUnit) {
        case 'm': convertedSpacing /= 1000; break;
        case 'cm': convertedSpacing /= 10; break;
        case 'ft': convertedSpacing /= 304.8; break;
        case 'in': convertedSpacing /= 25.4; break;
    }
    const spacingInPdfUnits = convertedSpacing / scaleFactor;
    const spacingInPixels = spacingInPdfUnits * currentRenderScale;
    if (spacingInPixels < 5) return;
    measureContext.beginPath();
    measureContext.strokeStyle = GRID_COLOR;
    measureContext.lineWidth = 0.5;
    measureContext.setLineDash([2, 2]);
    for (let x = 0; x < canvasWidth; x += spacingInPixels) {
        measureContext.moveTo(x, 0);
        measureContext.lineTo(x, canvasHeight);
    }
    for (let y = 0; y < canvasHeight; y += spacingInPixels) {
        measureContext.moveTo(0, y);
        measureContext.lineTo(canvasWidth, y);
    }
    measureContext.stroke();
    measureContext.setLineDash([]);
}

function handleMouseDownOnCanvas(event) {
    if (!pdfDoc || event.button !== 0) return;
    const clickPdfPoint = getPdfPoint(event.clientX, event.clientY);
    if (!clickPdfPoint) return;
    if (currentTool === 'none') {
        if (tryToStartDrag(clickPdfPoint)) event.preventDefault();
        else { selectedMeasurementIndex = -1; redrawAllElements(); }
        return;
    }
    currentPoints.push(clickPdfPoint);
    switch (currentTool) {
        case 'calibrate':
            if (currentPoints.length >= 2) if (calibrationInputDiv) calibrationInputDiv.style.display = 'block';
            break;
        case 'distance':
            if (currentPoints.length >= 2) {
                const dist = calculateDistance(currentPoints[0], currentPoints[1]) * (scaleFactor || 1);
                allMeasurements.push({ type: 'distance', pointsPdf: [...currentPoints], value: dist, unit: realWorldUnit, pageNum: currentPageNum });
                updateMeasurementsList();
                setActiveTool('none');
            }
            break;
    }
    redrawAllElements();
}

function tryToStartDrag(clickPdfPoint) { for (let i = allMeasurements.length - 1; i >= 0; i--) { const m = allMeasurements[i]; if (m.pageNum !== currentPageNum) continue; for (let j = 0; j < m.pointsPdf.length; j++) { const screenPoint = getScreenPoint(m.pointsPdf[j]); const clickScreenPoint = getScreenPoint(clickPdfPoint); const distance = Math.hypot(clickScreenPoint.x - screenPoint.x, clickScreenPoint.y - screenPoint.y); if (distance < DRAG_HANDLE_RADIUS) { isDraggingPoint = true; selectedMeasurementIndex = i; selectedPointIndex = j; document.addEventListener('mousemove', handleMouseMoveDocument); document.addEventListener('mouseup', handleMouseUpDocument); updateUI(); return true; } } } return false; }
function handleMouseMoveDocument(event) { if (!isDraggingPoint) return; const currentPdfMousePoint = getPdfPoint(event.clientX, event.clientY); if (!currentPdfMousePoint) return; const measurement = allMeasurements[selectedMeasurementIndex]; measurement.pointsPdf[selectedPointIndex] = currentPdfMousePoint; if(measurement.type === 'distance') { measurement.value = calculateDistance(measurement.pointsPdf[0], measurement.pointsPdf[1]) * (scaleFactor || 1); } else if (measurement.type === 'area' && measurement.pointsPdf.length > 2) { measurement.value = calculateAreaShoelace(measurement.pointsPdf) * (scaleFactor ? scaleFactor*scaleFactor : 1); } redrawAllElements(); }
function handleMouseUpDocument(event) { isDraggingPoint = false; document.removeEventListener('mousemove', handleMouseMoveDocument); document.removeEventListener('mouseup', handleMouseUpDocument); updateMeasurementsList(); updateUI(); }
function getPdfPoint(clientX, clientY) { if (!currentViewport) return null; const rect = measureCanvas.getBoundingClientRect(); const x = clientX - rect.left; const y = clientY - rect.top; const pdfPoint = currentViewport.convertToPdfPoint(x, y); return { x: pdfPoint[0], y: pdfPoint[1] }; }
function getScreenPoint(pdfPoint) { if (!currentViewport) return null; const sp = currentViewport.convertToViewportPoint(pdfPoint.x, pdfPoint.y); return {x: sp[0], y: sp[1]}; }
function drawMeasurement(measurement, isSelected) { const screenPoints = measurement.pointsPdf.map(p => getScreenPoint(p)); const color = isSelected ? LINE_COLOR_SELECTED : LINE_COLOR_MEASURE; if (measurement.type === 'distance' && screenPoints.length === 2) { drawLine(screenPoints[0], screenPoints[1], color); const midPoint = { x: (screenPoints[0].x + screenPoints[1].x) / 2, y: (screenPoints[0].y + screenPoints[1].y) / 2 }; drawText(`${measurement.value.toFixed(2)} ${measurement.unit}`, midPoint); } else if (measurement.type === 'area' && screenPoints.length > 1) { drawPolygon(screenPoints, LINE_COLOR_AREA, FILL_COLOR_AREA, true); const center = getPolygonCentroid(screenPoints); drawText(`${measurement.value.toFixed(2)} ${measurement.unit}²`, center); } if (isSelected) { screenPoints.forEach(p => drawPoint(p, LINE_COLOR_SELECTED, DRAG_HANDLE_RADIUS)); } }
function drawInProgress() { const screenPoints = currentPoints.map(p => getScreenPoint(p)); if (screenPoints.length === 0) return; screenPoints.forEach(p => drawPoint(p, POINT_COLOR_CALIBRATE, POINT_RADIUS)); if (!currentMousePosPdf) return; const mouseScreenPos = getScreenPoint(currentMousePosPdf); const lastPoint = screenPoints[screenPoints.length - 1]; const color = currentTool === 'calibrate' ? 'red' : 'blue'; switch(currentTool) { case 'calibrate': case 'distance': if (screenPoints.length > 0) { drawLine(lastPoint, mouseScreenPos, color, true); } break; case 'area': if (screenPoints.length === 1) { drawLine(screenPoints[0], mouseScreenPos, color, true); } else if (screenPoints.length > 1) { const tempPoints = [...screenPoints, mouseScreenPos]; drawPolygon(tempPoints, LINE_COLOR_AREA, FILL_COLOR_AREA, false); drawLine(mouseScreenPos, screenPoints[0], 'purple', true); } break; } }
function drawPoint(screenPoint, color, radius) { measureContext.beginPath(); measureContext.arc(screenPoint.x, screenPoint.y, radius, 0, 2 * Math.PI); measureContext.fillStyle = color; measureContext.fill(); }
function drawLine(p1, p2, color, isDashed = false) { measureContext.beginPath(); if(isDashed) measureContext.setLineDash([5, 5]); measureContext.moveTo(p1.x, p1.y); measureContext.lineTo(p2.x, p2.y); measureContext.strokeStyle = color; measureContext.lineWidth = 2; measureContext.stroke(); if(isDashed) measureContext.setLineDash([]); }
function drawPolygon(points, stroke, fill, close) { if (!points || points.length < 1) return; measureContext.beginPath(); measureContext.moveTo(points[0].x, points[0].y); for (let i = 1; i < points.length; i++) { measureContext.lineTo(points[i].x, points[i].y); } if (close) measureContext.closePath(); measureContext.strokeStyle = stroke; measureContext.lineWidth = 2; measureContext.stroke(); if (fill) { measureContext.fillStyle = fill; measureContext.fill(); } }
function drawText(text, pos) { measureContext.font = TEXT_FONT; const width = measureContext.measureText(text).width; measureContext.fillStyle = TEXT_BG_COLOR; measureContext.fillRect(pos.x - width/2 - 2, pos.y - 14, width + 4, 14); measureContext.fillStyle = TEXT_COLOR; measureContext.textAlign = 'center'; measureContext.fillText(text, pos.x, pos.y - 2); }
function getPolygonCentroid(pts) { let first = pts[0], last = pts[pts.length - 1]; if (first.x != last.x || first.y != last.y) pts.push(first); let twicearea = 0, x = 0, y = 0, nPts = pts.length, p1, p2, f; for (let i = 0, j = nPts - 1; i < nPts; j = i++) { p1 = pts[i]; p2 = pts[j]; f = p1.x * p2.y - p2.x * p1.y; twicearea += f; x += (p1.x + p2.x) * f; y += (p1.y + p2.y) * f; } f = twicearea * 3; return { x: x / f, y: y / f }; }
function calculateDistance(p1, p2) { return Math.hypot(p2.x - p1.x, p2.y - p1.y); }
function calculateAreaShoelace(points) { let area = 0; for (let i = 0; i < points.length; i++) { const j = (i + 1) % points.length; area += points[i].x * points[j].y; area -= points[j].x * points[i].y; } return Math.abs(area / 2); }
function updateMeasurementsList() { if(!measurementsListEl) return; measurementsListEl.innerHTML = ''; const measurementsOnPage = allMeasurements.filter(m => m.pageNum === currentPageNum); measurementsOnPage.forEach((m, i) => { const li = document.createElement('li'); li.className = 'list-group-item'; li.textContent = `Medida ${i + 1}: ${m.value.toFixed(2)} ${m.unit}${m.type==='area'?'²':''}`; measurementsListEl.appendChild(li); }); }
function resetApplicationState() { pdfDoc=null; currentPageNum=1; currentRenderScale = RENDER_SCALE_INITIAL; pageRendering=false; pageNumPending=null; currentViewport=null; currentTool='none'; currentPoints=[]; allMeasurements=[]; selectedMeasurementIndex=-1; selectedPointIndex=-1; isDraggingPoint=false; scaleFactor=null; realWorldUnit='mm'; updateUI(); updateMeasurementsList(); if (currentScaleInfoEl) currentScaleInfoEl.textContent = 'No Cal.'; if (pageSizeInfoEl) pageSizeInfoEl.textContent = '--'; }
function showTemporaryMessage(message, type = 'info') { const messageDiv = document.createElement('div'); messageDiv.textContent = message; messageDiv.style.position = 'fixed'; messageDiv.style.top = '20px'; messageDiv.style.left = '50%'; messageDiv.style.transform = 'translateX(-50%)'; messageDiv.style.padding = '10px 20px'; messageDiv.style.borderRadius = '5px'; messageDiv.style.color = 'white'; messageDiv.style.zIndex = '1050'; const colors = { warning: '#ffc107', error: '#dc3545', success: '#198754' }; messageDiv.style.backgroundColor = colors[type] || '#0dcaf0'; document.body.appendChild(messageDiv); setTimeout(() => { messageDiv.style.opacity = '1'; }, 10); setTimeout(() => { messageDiv.style.opacity = '0'; setTimeout(() => { document.body.removeChild(messageDiv); }, 300); }, 3000); }


document.addEventListener('DOMContentLoaded', () => {
    if (measureDistanceBtn) measureDistanceBtn.addEventListener('click', () => setActiveTool('distance'));
    if (measureAreaBtn) measureAreaBtn.addEventListener('click', () => setActiveTool('area'));
    if (startCalibrateBtn) startCalibrateBtn.addEventListener('click', () => setActiveTool('calibrate'));
    if (resetScaleBtn) {
        resetScaleBtn.addEventListener('click', () => {
            scaleFactor = null;
            if (currentScaleInfoEl) currentScaleInfoEl.textContent = 'No Cal.';
            setActiveTool('none'); 
            if(gridEnabled) {
                toggleGridBtn.checked = false;
                gridEnabled = false;
                if(gridControlsDiv) gridControlsDiv.style.display = 'none';
            }
            redrawAllElements();
            showTemporaryMessage('Escala reiniciada.', 'info');
        });
    }
    if (finishShapeBtn) {
        finishShapeBtn.addEventListener('click', () => {
            if (currentTool === 'area' && currentPoints.length >= 3) {
                const area = calculateAreaShoelace(currentPoints) * (scaleFactor ? scaleFactor*scaleFactor : 1);
                allMeasurements.push({ type: 'area', pointsPdf: [...currentPoints], value: area, unit: realWorldUnit, pageNum: currentPageNum });
                updateMeasurementsList();
            }
            setActiveTool('none');
        });
    }
    if (clearMeasurementsBtn) {
        clearMeasurementsBtn.addEventListener('click', () => {
            if (confirm("¿Estás seguro de que quieres borrar todas las mediciones de ESTA PÁGINA?")) {
                allMeasurements = allMeasurements.filter(m => m.pageNum !== currentPageNum);
                currentPoints = [];
                selectedMeasurementIndex = -1;
                updateUI();
                updateMeasurementsList();
            }
        });
    }
    if (setScaleBtn) {
        setScaleBtn.addEventListener('click', () => {
            const knownLength = parseFloat(knownLengthInput.value);
            if (isNaN(knownLength) || knownLength <= 0) { alert("Longitud inválida"); return; }
            if (currentTool === 'calibrate' && currentPoints.length === 2) {
                const pdfDist = calculateDistance(currentPoints[0], currentPoints[1]);
                scaleFactor = knownLength / pdfDist;
                realWorldUnit = knownUnitSelect.value;
                if (currentScaleInfoEl) currentScaleInfoEl.textContent = `1:${(1/scaleFactor).toFixed(2)} (calc)`;
                if (calibrationInputDiv) calibrationInputDiv.style.display = 'none';
                setActiveTool('none');
                redrawAllElements();
            } else { alert("Primero dibuja una línea de calibración de dos puntos."); }
        });
    }
    if (applyPredefinedScaleBtn) {
        applyPredefinedScaleBtn.addEventListener('click', () => {
            const selected = predefinedScaleSelect.value;
            if (!selected) { alert("Selecciona una escala"); return; }
            const mm_per_pt = 25.4 / 72;
            const scaleRatio = parseFloat(selected);
            realWorldUnit = knownUnitSelect.value;
            let factor = mm_per_pt * scaleRatio;
            switch(realWorldUnit) {
                case 'm':  factor /= 1000; break;
                case 'cm': factor /= 10; break;
                case 'mm': break;
                case 'ft': factor /= 304.8; break;
                case 'in': factor /= 25.4; break;
            }
            scaleFactor = factor;
            if (currentScaleInfoEl) currentScaleInfoEl.textContent = `1:${scaleRatio} (${realWorldUnit})`;
            showTemporaryMessage(`Escala 1:${scaleRatio} aplicada.`, 'success');
            setActiveTool('none');
            redrawAllElements();
        });
    }

    if (zoomInBtn) zoomInBtn.addEventListener('click', () => { currentRenderScale += ZOOM_FACTOR; renderPage(currentPageNum); });
    if (zoomOutBtn) zoomOutBtn.addEventListener('click', () => { if (currentRenderScale > ZOOM_FACTOR) { currentRenderScale -= ZOOM_FACTOR; renderPage(currentPageNum); } });
    if (prevPageBtn) prevPageBtn.addEventListener('click', () => { if (pdfDoc && currentPageNum > 1) renderPage(currentPageNum - 1); });
    if (nextPageBtn) nextPageBtn.addEventListener('click', () => { if (pdfDoc && currentPageNum < pdfDoc.numPages) renderPage(currentPageNum + 1); });
    if (goToPageBtn) goToPageBtn.addEventListener('click', () => { if(pdfDoc) {const page = parseInt(goToPageInput.value); if (page >= 1 && page <= pdfDoc.numPages) renderPage(page);} });
    
    if (toggleGridBtn) {
        toggleGridBtn.addEventListener('change', () => {
            gridEnabled = toggleGridBtn.checked;
            if (gridEnabled && !scaleFactor) {
                showTemporaryMessage("Calibra la escala primero para usar la cuadrícula.", "warning");
                toggleGridBtn.checked = false;
                gridEnabled = false;
                return;
            }
            if(gridControlsDiv) gridControlsDiv.style.display = gridEnabled ? 'block' : 'none';
            redrawAllElements();
        });
    }
    if (gridSpacingInput) gridSpacingInput.addEventListener('input', () => { if(gridEnabled) redrawAllElements(); });
    if (gridUnitSelect) gridUnitSelect.addEventListener('change', () => { if(gridEnabled) redrawAllElements(); });

    if (measureCanvas) {
        measureCanvas.addEventListener('mousedown', handleMouseDownOnCanvas);
        measureCanvas.addEventListener('mousemove', (e) => {
            if (!pdfDoc) return;
            currentMousePosPdf = getPdfPoint(e.clientX, e.clientY);
            if (currentTool !== 'none' && currentPoints.length > 0) redrawAllElements();
        });
    }
    
    // Lógica de carga inicial
    if (PDF_URL_TO_LOAD) {
        if (PDF_FILENAME && loadedPdfNameEl) {
            loadedPdfNameEl.textContent = PDF_FILENAME;
        }
        loadAndRenderPdf(PDF_URL_TO_LOAD);
    }
});