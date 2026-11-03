
"use strict";

/* =========================================
   STEGOSAFE - IMAGE STEGANOGRAPHY
   LSB + AES-256-CBC + PBKDF2 SHA-256
   All processing takes place locally.
========================================= */

const $ = (id) => document.getElementById(id);

const MAGIC = new Uint8Array([83, 84, 71, 79]); // STGO
const VERSION = 1;
const HEADER_SIZE = 4 + 1 + 4; // Magic + version + payload length
const SALT_SIZE = 16;
const IV_SIZE = 16;
const ITERATIONS = 250000;
const MAX_IMAGE_PIXELS = 16000000;
const MAX_FILE_SIZE = 25 * 1024 * 1024;

let coverData = null;
let extractData = null;
let generatedBlob = null;
let recoveredMessage = "";
let coverObjectURL = null;
let extractObjectURL = null;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/* =========================================
   UI HELPERS
========================================= */

function showStatus(id, message, type = "info") {
    const element = $(id);
    element.textContent = message;
    element.className = `status-message ${type}`;
}

function clearStatus(id) {
    $(id).textContent = "";
    $(id).className = "status-message hidden";
}

function setLoading(button, loading, text) {
    if (loading) {
        button.dataset.originalText = button.innerHTML;
        button.disabled = true;
        button.textContent = "Processing...";
    } else {
        button.disabled = false;
        button.innerHTML = button.dataset.originalText || text;
    }
}

function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} Bytes`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function bytesToBase64(bytes) {
    let binary = "";
    const chunkSize = 8192;

    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
    }

    return btoa(binary);
}

function base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

function concatBytes(...arrays) {
    const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(total);

    let offset = 0;

    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }

    return result;
}

function arraysEqual(a, b) {
    if (a.length !== b.length) return false;

    let difference = 0;

    for (let i = 0; i < a.length; i++) {
        difference |= a[i] ^ b[i];
    }

    return difference === 0;
}

/* =========================================
   TABS
========================================= */

document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
        document.querySelectorAll(".tab").forEach(item => {
            item.classList.remove("active");
        });

        document.querySelectorAll(".tab-panel").forEach(panel => {
            panel.classList.remove("active");
        });

        tab.classList.add("active");
        $(`${tab.dataset.tab}Panel`).classList.add("active");
    });
});

/* =========================================
   PASSWORD VISIBILITY
========================================= */

document.querySelectorAll(".toggle-password").forEach(button => {
    button.addEventListener("click", () => {
        const input = $(button.dataset.target);

        input.type = input.type === "password" ? "text" : "password";
    });
});

/* =========================================
   IMAGE LOADING
========================================= */

function validateFile(file) {
    if (!file) throw new Error("Please select an image.");

    if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
        throw new Error("Unsupported format. Select PNG, JPEG or WEBP.");
    }

    if (file.size > MAX_FILE_SIZE) {
        throw new Error("Image is too large. Maximum file size is 25 MB.");
    }

    if (!file.size) {
        throw new Error("The selected file is empty.");
    }
}

function loadImage(file) {
    return new Promise((resolve, reject) => {
        const url = URL.createObjectURL(file);
        const image = new Image();

        image.onload = () => {
            if (!image.naturalWidth || !image.naturalHeight) {
                URL.revokeObjectURL(url);
                reject(new Error("Invalid image dimensions."));
                return;
            }

            if (image.naturalWidth * image.naturalHeight > MAX_IMAGE_PIXELS) {
                URL.revokeObjectURL(url);
                reject(new Error("Image is too large to process safely. Maximum 16 megapixels."));
                return;
            }

            resolve({ image, url });
        };

        image.onerror = () => {
            URL.revokeObjectURL(url);
            reject(new Error("Unable to read this image. Please select a valid image."));
        };

        image.src = url;
    });
}

function imageToCanvas(image) {
    const canvas = document.createElement("canvas");

    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;

    const ctx = canvas.getContext("2d", {
        willReadFrequently: true
    });

    if (!ctx) throw new Error("Canvas is not supported.");

    ctx.drawImage(image, 0, 0);

    return {
        canvas,
        ctx,
        imageData: ctx.getImageData(0, 0, canvas.width, canvas.height)
    };
}

function releaseCover() {
    if (coverObjectURL) URL.revokeObjectURL(coverObjectURL);

    coverObjectURL = null;
    coverData = null;

    $("coverInput").value = "";
    $("coverPreview").classList.add("hidden");
    $("coverDrop").classList.remove("hidden");

    updateCapacity();
}

function releaseExtract() {
    if (extractObjectURL) URL.revokeObjectURL(extractObjectURL);

    extractObjectURL = null;
    extractData = null;

    $("extractInput").value = "";
    $("extractPreview").classList.add("hidden");
    $("extractDrop").classList.remove("hidden");
}

async function handleImageSelection(file, mode) {
    validateFile(file);

    const result = await loadImage(file);

    if (mode === "cover") {
        if (coverObjectURL) URL.revokeObjectURL(coverObjectURL);

        coverObjectURL = result.url;

        coverData = {
            image: result.image,
            name: file.name,
            width: result.image.naturalWidth,
            height: result.image.naturalHeight
        };

        $("coverImage").src = result.url;
        $("coverName").textContent = file.name;
        $("coverDimensions").textContent =
            `${coverData.width} × ${coverData.height}`;

        $("coverPreview").classList.remove("hidden");
        $("coverDrop").classList.add("hidden");

        updateCapacity();
        clearStatus("hideStatus");

    } else {
        if (extractObjectURL) URL.revokeObjectURL(extractObjectURL);

        extractObjectURL = result.url;

        extractData = {
            image: result.image,
            name: file.name,
            width: result.image.naturalWidth,
            height: result.image.naturalHeight
        };

        $("extractImage").src = result.url;
        $("extractName").textContent = file.name;
        $("extractDimensions").textContent =
            `${extractData.width} × ${extractData.height}`;

        $("extractPreview").classList.remove("hidden");
        $("extractDrop").classList.add("hidden");

        clearStatus("extractStatus");
    }
}

$("coverInput").addEventListener("change", async event => {
    try {
        if (event.target.files[0]) {
            await handleImageSelection(event.target.files[0], "cover");
        }
    } catch (error) {
        showStatus("hideStatus", error.message, "error");
    }
});

$("extractInput").addEventListener("change", async event => {
    try {
        if (event.target.files[0]) {
            await handleImageSelection(event.target.files[0], "extract");
        }
    } catch (error) {
        showStatus("extractStatus", error.message, "error");
    }
});

$("removeCover").addEventListener("click", releaseCover);
$("removeExtract").addEventListener("click", releaseExtract);

/* =========================================
   DRAG AND DROP
========================================= */

function setupDropZone(zoneId, inputId, mode) {
    const zone = $(zoneId);

    ["dragenter", "dragover"].forEach(type => {
        zone.addEventListener(type, event => {
            event.preventDefault();
            zone.classList.add("dragging");
        });
    });

    ["dragleave", "drop"].forEach(type => {
        zone.addEventListener(type, event => {
            event.preventDefault();
            zone.classList.remove("dragging");
        });
    });

    zone.addEventListener("drop", async event => {
        const file = event.dataTransfer.files[0];

        try {
            await handleImageSelection(file, mode);
            $(inputId).value = "";
        } catch (error) {
            showStatus(
                mode === "cover" ? "hideStatus" : "extractStatus",
                error.message,
                "error"
            );
        }
    });
}

setupDropZone("coverDrop", "coverInput", "cover");
setupDropZone("extractDrop", "extractInput", "extract");

/* =========================================
   MESSAGE COUNTER AND CAPACITY
========================================= */

$("secretMessage").addEventListener("input", () => {
    $("charCount").textContent =
        `${$("secretMessage").value.length} / 100000`;
});

function getCapacityBytes(width, height) {
    const totalRGBChannels = width * height * 3;
    const totalBits = totalRGBChannels;

    // Header uses 72 bits; payload uses 8 bits per byte.
    return Math.floor((totalBits - HEADER_SIZE * 8) / 8);
}

function updateCapacity(payloadLength = null) {
    if (!coverData) {
        $("capacityText").textContent = "Upload an image first";
        $("capacityBar").style.width = "0%";
        return;
    }

    const capacity = getCapacityBytes(coverData.width, coverData.height);

    if (capacity < 0) {
        $("capacityText").textContent = "Image too small";
        return;
    }

    $("capacityText").textContent = `${formatBytes(capacity)} available`;

    if (payloadLength !== null) {
        const percentage = capacity
            ? Math.min((payloadLength / capacity) * 100, 100)
            : 0;

        $("capacityBar").style.width = `${percentage}%`;
    } else {
        $("capacityBar").style.width = "0%";
    }
}

/* =========================================
   AES-256-CBC ENCRYPTION
   PBKDF2 / SHA-256
========================================= */

async function deriveKey(password, salt) {
    const passwordKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: ITERATIONS,
            hash: "SHA-256"
        },
        passwordKey,
        {
            name: "AES-CBC",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptMessage(message, password) {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
    const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));

    const key = await deriveKey(password, salt);

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-CBC", iv },
        key,
        encoder.encode(message)
    );

    /*
       Payload format:
       0:  Version
       1:  Encryption flag (1)
       2-17: Salt
       18-33: IV
       34+: Ciphertext
    */

    return concatBytes(
        new Uint8Array([VERSION, 1]),
        salt,
        iv,
        new Uint8Array(encrypted)
    );
}

async function decryptMessage(payload, password) {
    if (!password) {
        throw new Error("This message is encrypted. Please enter its password.");
    }

    if (payload.length < 2 + SALT_SIZE + IV_SIZE + 16) {
        throw new Error("Encrypted payload is incomplete or corrupted.");
    }

    const version = payload[0];
    const encryptedFlag = payload[1];

    if (version !== VERSION || encryptedFlag !== 1) {
        throw new Error("Unsupported encrypted payload.");
    }

    let offset = 2;

    const salt = payload.slice(offset, offset + SALT_SIZE);
    offset += SALT_SIZE;

    const iv = payload.slice(offset, offset + IV_SIZE);
    offset += IV_SIZE;

    const ciphertext = payload.slice(offset);

    if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
        throw new Error("Encrypted data is incomplete or corrupted.");
    }

    const key = await deriveKey(password, salt);

    try {
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-CBC", iv },
            key,
            ciphertext
        );

        return decoder.decode(decrypted);

    } catch {
        throw new Error("Incorrect password or corrupted encrypted data.");
    }
}

/* =========================================
   PAYLOAD FORMAT
=========================================

   Main LSB payload:
   Bytes 0-3 : ASCII magic "STGO"
   Byte 4    : Version (1)
   Bytes 5-8 : Payload length (unsigned big-endian)
   Bytes 9+  : Payload bytes

   Plain payload:
   Byte 0    : Version
   Byte 1    : Encryption flag (0)
   Bytes 2+  : UTF-8 message

   Encrypted payload:
   Byte 0    : Version
   Byte 1    : Encryption flag (1)
   Bytes 2-17: Salt
   Bytes 18-33: IV
   Bytes 34+: AES-CBC ciphertext
========================================= */

function createPayload(messageBytes) {
    return concatBytes(
        new Uint8Array([VERSION, 0]),
        messageBytes
    );
}

function createHeader(payloadLength) {
    if (!Number.isSafeInteger(payloadLength) ||
        payloadLength < 2 ||
        payloadLength > 0xffffffff) {
        throw new Error("Invalid message size.");
    }

    const header = new Uint8Array(HEADER_SIZE);

    header.set(MAGIC, 0);
    header[4] = VERSION;

    new DataView(header.buffer).setUint32(
        5,
        payloadLength,
        false
    );

    return header;
}

/* =========================================
   LSB ENCODING
========================================= */

function encodeLSB(imageData, payload) {
    const pixels = imageData.data;
    const totalChannels = imageData.width * imageData.height * 3;

    const header = createHeader(payload.length);
    const completeData = concatBytes(header, payload);

    const requiredBits = completeData.length * 8;

    if (requiredBits > totalChannels) {
        throw new Error("Image capacity is insufficient for this message. Choose a larger image or shorten the message.");
    }

    let bitPosition = 0;

    for (let byteIndex = 0; byteIndex < completeData.length; byteIndex++) {
        for (let bit = 7; bit >= 0; bit--) {
            const value = (completeData[byteIndex] >> bit) & 1;

            // Map each bit to R, G, B. Skip alpha.
            const pixelIndex = Math.floor(bitPosition / 3);
            const channel = bitPosition % 3;
            const dataIndex = pixelIndex * 4 + channel;

            pixels[dataIndex] =
                (pixels[dataIndex] & 0xFE) | value;

            bitPosition++;
        }
    }

    return imageData;
}

/* =========================================
   LSB EXTRACTION
========================================= */

function extractLSB(imageData) {
    const pixels = imageData.data;
    const totalChannels = imageData.width * imageData.height * 3;

    function readBytes(startBit, byteCount) {
        const bytes = new Uint8Array(byteCount);
        const required = byteCount * 8;

        if (startBit + required > totalChannels) {
            throw new Error("The image does not contain a complete payload.");
        }

        for (let i = 0; i < byteCount; i++) {
            let value = 0;

            for (let bit = 0; bit < 8; bit++) {
                const position = startBit + i * 8 + bit;
                const pixelIndex = Math.floor(position / 3);
                const channel = position % 3;
                const dataIndex = pixelIndex * 4 + channel;

                value = (value << 1) | (pixels[dataIndex] & 1);
            }

            bytes[i] = value;
        }

        return bytes;
    }

    const header = readBytes(0, HEADER_SIZE);

    if (!arraysEqual(header.slice(0, 4), MAGIC)) {
        throw new Error("No StegoSafe hidden message was found in this image.");
    }

    if (header[4] !== VERSION) {
        throw new Error("Unsupported StegoSafe payload version.");
    }

    const payloadLength = new DataView(
        header.buffer,
        header.byteOffset,
        header.byteLength
    ).getUint32(5, false);

    const maximumLength = Math.floor(totalChannels / 8) - HEADER_SIZE;

    if (
        payloadLength < 2 ||
        payloadLength > maximumLength
    ) {
        throw new Error("Invalid payload length. The image may be corrupted.");
    }

    const payload = readBytes(
        HEADER_SIZE * 8,
        payloadLength
    );

    return payload;
}

/* =========================================
   GENERATE PNG
========================================= */

function canvasToBlob(canvas) {
    return new Promise((resolve, reject) => {
        canvas.toBlob(blob => {
            if (blob) resolve(blob);
            else reject(new Error("Unable to generate PNG image."));
        }, "image/png");
    });
}

async function hideMessage() {
    const button = $("hideButton");

    clearStatus("hideStatus");

    if (!coverData) {
        showStatus("hideStatus", "Please upload a cover image first.", "error");
        return;
    }

    const message = $("secretMessage").value;
    const password = $("hidePassword").value;

    if (!message.trim()) {
        showStatus("hideStatus", "Please enter a secret message.", "error");
        return;
    }

    if (message.length > 100000) {
        showStatus("hideStatus", "Message is too long.", "error");
        return;
    }

    if (!window.crypto || !crypto.subtle) {
        showStatus("hideStatus", "Web Crypto is unavailable. Use HTTPS or localhost.", "error");
        return;
    }

    setLoading(button, true);

    try {
        showStatus("hideStatus", "Preparing message payload...", "info");

        const canvasData = imageToCanvas(coverData.image);

        const messageBytes = encoder.encode(message);

        let payload;

        if (password.length > 0) {
            if (password.length < 8) {
                throw new Error("Use at least 8 characters for an encryption password.");
            }

            showStatus("hideStatus", "Encrypting message with AES-256...", "info");

            payload = await encryptMessage(message, password);

        } else {
            payload = createPayload(messageBytes);
        }

        const capacity = getCapacityBytes(
            canvasData.canvas.width,
            canvasData.canvas.height
        );

        if (payload.length > capacity) {
            throw new Error(
                `Insufficient image capacity. Available: ${formatBytes(capacity)}, Required: ${formatBytes(payload.length)}.`
            );
        }

        showStatus("hideStatus", "Embedding message into RGB pixels...", "info");

        encodeLSB(canvasData.imageData, payload);

        canvasData.ctx.putImageData(
            canvasData.imageData,
            0,
            0
        );

        generatedBlob = await canvasToBlob(canvasData.canvas);

        if (generatedBlob.type !== "image/png") {
            throw new Error("PNG generation failed.");
        }

        if (window.outputObjectURL) {
            URL.revokeObjectURL(window.outputObjectURL);
        }

        window.outputObjectURL = URL.createObjectURL(generatedBlob);

        $("outputImage").src = window.outputObjectURL;
        $("outputImage").classList.remove("hidden");

        $("outputPreview").querySelector(".empty-state").classList.add("hidden");

        $("outputDetails").classList.remove("hidden");
        $("outputSize").textContent = formatBytes(payload.length);
        $("outputSecurity").textContent =
            password ? "AES-256 ENCRYPTED" : "PLAIN TEXT";

        $("downloadButton").disabled = false;

        updateCapacity(payload.length);

        showStatus(
            "hideStatus",
            "Success! Your secret message has been hidden inside the image.",
            "success"
        );

    } catch (error) {
        showStatus("hideStatus", error.message || "Unable to process image.", "error");

    } finally {
        setLoading(button, false);
    }
}

$("hideButton").addEventListener("click", hideMessage);

/* =========================================
   DOWNLOAD PROTECTED IMAGE
========================================= */

$("downloadButton").addEventListener("click", () => {
    if (!generatedBlob) return;

    const url = URL.createObjectURL(generatedBlob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "StegoSafe_Protected_Image.png";

    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);
});

/* =========================================
   EXTRACT AND DECRYPT
========================================= */

async function extractMessage() {
    const button = $("extractButton");

    clearStatus("extractStatus");

    if (!extractData) {
        showStatus("extractStatus", "Please upload an image first.", "error");
        return;
    }

    if (!window.crypto || !crypto.subtle) {
        showStatus("extractStatus", "Web Crypto is unavailable. Use HTTPS or localhost.", "error");
        return;
    }

    setLoading(button, true);

    try {
        showStatus("extractStatus", "Reading image pixels...", "info");

        const canvasData = imageToCanvas(extractData.image);

        showStatus("extractStatus", "Searching for hidden payload...", "info");

        const payload = extractLSB(canvasData.imageData);

        if (payload.length < 2 || payload[0] !== VERSION) {
            throw new Error("Invalid or unsupported message payload.");
        }

        const encryptedFlag = payload[1];

        let recovered;

        if (encryptedFlag === 1) {
            showStatus("extractStatus", "Encrypted message detected. Decrypting...", "info");

            const password = $("extractPassword").value;

            recovered = await decryptMessage(payload, password);

        } else if (encryptedFlag === 0) {
            const messageBytes = payload.slice(2);

            try {
                recovered = decoder.decode(messageBytes);
            } catch {
                throw new Error("Message contains invalid UTF-8 data.");
            }

        } else {
            throw new Error("Unknown message encryption format.");
        }

        recoveredMessage = recovered;

        $("recoveredBox").innerHTML = "";

        const messageElement = document.createElement("div");
        messageElement.className = "message-content";
        messageElement.textContent = recovered;

        $("recoveredBox").appendChild(messageElement);

        $("recoveryInfo").classList.remove("hidden");

        $("recoveryType").textContent =
            encryptedFlag === 1 ? "AES-256 ENCRYPTED" : "PLAIN TEXT";

        $("copyButton").disabled = false;

        showStatus(
            "extractStatus",
            "Message recovered successfully!",
            "success"
        );

    } catch (error) {
        recoveredMessage = "";

        $("recoveredBox").innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">⚠</div>
                <h4>Recovery Failed</h4>
                <p>Unable to recover the hidden message.</p>
            </div>
        `;

        $("recoveryInfo").classList.add("hidden");
        $("copyButton").disabled = true;

        showStatus(
            "extractStatus",
            error.message || "Unable to extract message.",
            "error"
        );

    } finally {
        setLoading(button, false);
    }
}

$("extractButton").addEventListener("click", extractMessage);

/* =========================================
   COPY RECOVERED MESSAGE
========================================= */

$("copyButton").addEventListener("click", async () => {
    if (!recoveredMessage) return;

    try {
        await navigator.clipboard.writeText(recoveredMessage);

        showStatus("extractStatus", "Recovered message copied successfully.", "success");

    } catch {
        showStatus("extractStatus", "Clipboard access is unavailable in this browser.", "error");
    }
});

/* =========================================
   CLEAR EXTRACTION PANEL
========================================= */

$("clearButton").addEventListener("click", () => {
    releaseExtract();

    $("extractPassword").value = "";

    $("recoveredBox").innerHTML = `
        <div class="empty-state">
            <div class="empty-icon">⌑</div>
            <h4>Waiting for Extraction</h4>
            <p>Your recovered message will appear here.</p>
        </div>
    `;

    $("recoveryInfo").classList.add("hidden");
    $("copyButton").disabled = true;

    recoveredMessage = "";

    clearStatus("extractStatus");
});

/* =========================================
   CLEAR GENERATED OUTPUT
========================================= */

function clearGeneratedOutput() {
    generatedBlob = null;

    if (window.outputObjectURL) {
        URL.revokeObjectURL(window.outputObjectURL);
        window.outputObjectURL = null;
    }

    $("outputImage").removeAttribute("src");
    $("outputImage").classList.add("hidden");

    $("outputPreview").querySelector(".empty-state").classList.remove("hidden");

    $("outputDetails").classList.add("hidden");
    $("downloadButton").disabled = true;
}

$("secretMessage").addEventListener("input", () => {
    clearGeneratedOutput();
    updateCapacity();
});

$("hidePassword").addEventListener("input", clearGeneratedOutput);

$("removeCover").addEventListener("click", () => {
    clearGeneratedOutput();
    clearStatus("hideStatus");
});

/* =========================================
   ANIMATED PARTICLE BACKGROUND
========================================= */

(function initializeParticles() {
    const canvas = $("particles");
    const ctx = canvas.getContext("2d");

    if (!ctx) return;

    let particles = [];
    let animationFrame;

    function resize() {
        const ratio = Math.min(window.devicePixelRatio || 1, 2);

        canvas.width = window.innerWidth * ratio;
        canvas.height = window.innerHeight * ratio;

        canvas.style.width = `${window.innerWidth}px`;
        canvas.style.height = `${window.innerHeight}px`;

        ctx.setTransform(ratio, 0, 0, ratio, 0, 0);

        const count = Math.min(
            Math.floor(window.innerWidth / 12),
            100
        );

        particles = Array.from({ length: count }, () => ({
            x: Math.random() * window.innerWidth,
            y: Math.random() * window.innerHeight,
            size: Math.random() * 2 + .5,
            speed: Math.random() * .35 + .12,
            opacity: Math.random() * .5 + .15
        }));
    }

    function draw() {
        ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);

        particles.forEach(particle => {
            particle.y -= particle.speed;

            if (particle.y < 0) {
                particle.y = window.innerHeight;
                particle.x = Math.random() * window.innerWidth;
            }

            ctx.beginPath();
            ctx.arc(
                particle.x,
                particle.y,
                particle.size,
                0,
                Math.PI * 2
            );

            ctx.fillStyle = `rgba(54, 167, 255, ${particle.opacity})`;
            ctx.fill();
        });

        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const a = particles[i];
                const b = particles[j];

                const dx = a.x - b.x;
                const dy = a.y - b.y;
                const distance = Math.sqrt(dx * dx + dy * dy);

                if (distance < 100) {
                    ctx.beginPath();
                    ctx.moveTo(a.x, a.y);
                    ctx.lineTo(b.x, b.y);

                    ctx.strokeStyle =
                        `rgba(45, 137, 255, ${.12 * (1 - distance / 100)})`;

                    ctx.lineWidth = .6;
                    ctx.stroke();
                }
            }
        }

        animationFrame = requestAnimationFrame(draw);
    }

    resize();
    draw();

    window.addEventListener("resize", resize);

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            cancelAnimationFrame(animationFrame);
        } else {
            cancelAnimationFrame(animationFrame);
            draw();
        }
    });
})();

/* =========================================
   INITIALIZATION
========================================= */

updateCapacity();

console.log("StegoSafe initialized. Local processing enabled.");
