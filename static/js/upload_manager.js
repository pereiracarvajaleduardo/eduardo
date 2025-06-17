// static/js/upload_manager.js (VERSIÓN DE DIAGNÓSTICO FINAL)

document.addEventListener('DOMContentLoaded', () => {
    console.log("DEBUG: DOM cargado. Script upload_manager.js iniciado.");

    const fileInput = document.getElementById('file-input');
    const uploadQueueWrapper = document.getElementById('upload-queue-wrapper');
    const uploadQueueDiv = document.getElementById('upload-queue');
    const startUploadBtn = document.getElementById('start-upload-btn');
    const MAX_FILES = 3;

    if (!fileInput || !uploadQueueWrapper || !uploadQueueDiv || !startUploadBtn) {
        console.error("Error crítico: No se encontraron los elementos del DOM. Revisa los IDs en upload_pdf.html.");
        return; 
    }
    console.log("DEBUG: Todos los elementos del DOM fueron encontrados correctamente.");

    let fileQueue = [];
    let isUploading = false;

    fileInput.addEventListener('change', (event) => {
        console.log("DEBUG: Evento 'change' del input detectado.");
        const files = Array.from(event.target.files);
        console.log(`DEBUG: Se seleccionaron ${files.length} archivos.`);

        if (files.length === 0) { resetUI(); return; }
        if (files.length > MAX_FILES) { alert(`Puedes seleccionar un máximo de ${MAX_FILES} archivos.`); resetUI(); return; }

        fileQueue = files;
        uploadQueueDiv.innerHTML = ''; 

        fileQueue.forEach((file, index) => {
            const fileElement = document.createElement('div');
            fileElement.className = 'd-flex justify-content-between align-items-center p-2 border-bottom';
            fileElement.id = `file-${file.name}-${index}`; // Usar un ID más único
            fileElement.innerHTML = `<span>${file.name}</span><span class="badge bg-secondary">Pendiente</span>`;
            uploadQueueDiv.appendChild(fileElement);
        });
        
        uploadQueueWrapper.style.display = 'block';
        startUploadBtn.disabled = false;
        startUploadBtn.textContent = `Iniciar Subida de ${files.length} Archivo(s)`;
        console.log("DEBUG: Interfaz actualizada. Listo para iniciar la subida.");
    });

    startUploadBtn.addEventListener('click', () => {
        console.log("DEBUG: Botón 'Iniciar Subida' presionado.");
        // --- NUEVO LOG DE DIAGNÓSTICO ---
        console.log(`DEBUG: Al hacer clic, la cola de archivos tiene ${fileQueue.length} elemento(s).`);
        
        if (isUploading || fileQueue.length === 0) {
            console.log("DEBUG: No se inicia el proceso porque isUploading es true o la cola está vacía.");
            return;
        }

        isUploading = true;
        startUploadBtn.disabled = true;
        fileInput.disabled = true;
        startUploadBtn.textContent = `Procesando...`;

        processQueue();
    });

    async function processQueue() {
        console.log(`DEBUG: Entrando a processQueue. Elementos restantes en cola: ${fileQueue.length}`);
        
        if (fileQueue.length === 0) {
            isUploading = false;
            startUploadBtn.textContent = '¡Subida Completada!';
            fileInput.disabled = false;
            console.log("DEBUG: Cola finalizada.");
            return;
        }

        const fileToUpload = fileQueue.shift(); // Toma el primer archivo de la cola
        
        // El índice es más fiable si lo calculamos sobre la selección original
        const originalFiles = Array.from(fileInput.files);
        const fileIndex = originalFiles.findIndex(f => f.name === fileToUpload.name && f.lastModified === fileToUpload.lastModified);

        console.log(`DEBUG: Procesando archivo: ${fileToUpload.name}`);
        await uploadFile(fileToUpload, fileIndex);
        
        processQueue();
    }

    async function uploadFile(file, index) {
        // Usamos un ID más robusto por si se suben archivos con el mismo nombre
        const fileElement = document.getElementById(`file-${file.name}-${index}`);
        const statusBadge = fileElement.querySelector('.badge');

        statusBadge.className = 'badge bg-primary';
        statusBadge.textContent = 'Subiendo...';

        const formData = new FormData();
        formData.append('file_to_upload', file);

        try {
            const response = await fetch('/upload', { method: 'POST', body: formData });
            const result = await response.json();
            if (response.ok) {
                statusBadge.className = 'badge bg-success';
                statusBadge.textContent = 'Éxito';
            } else {
                statusBadge.className = 'badge bg-danger';
                statusBadge.textContent = 'Error';
                fileElement.title = result.message;
            }
        } catch (error) {
            statusBadge.className = 'badge bg-danger';
            statusBadge.textContent = 'Error de Red';
            fileElement.title = 'No se pudo conectar con el servidor.';
        }
    }

    function resetUI() {
        fileQueue = [];
        uploadQueueDiv.innerHTML = '';
        if (uploadQueueWrapper) uploadQueueWrapper.style.display = 'none';
        if (fileInput) fileInput.value = '';
        if (startUploadBtn) {
            startUploadBtn.disabled = true;
            startUploadBtn.textContent = 'Por favor, selecciona archivos';
        }
    }
});