/**
 * @typedef {Object} ImageHeader
 * @property {Uint8Array} otaUpgradeFileIdentifier // read-only
 * @property {number} otaHeaderVersion // read-only
 * @property {number} otaHeaderLength // read-only / auto-computed
 * @property {number} otaHeaderFieldControl // read-only / auto-computed
 * @property {number} manufacturerCode
 * @property {number} imageType
 * @property {number} fileVersion
 * @property {number} zigbeeStackVersion
 * @property {string} otaHeaderString
 * @property {number} totalImageSize
 * @property {number | undefined} securityCredentialVersion
 * @property {Uint8Array | undefined} upgradeFileDestination
 * @property {number | undefined} minimumHardwareVersion
 * @property {number | undefined} maximumHardwareVersion
 *
 * @typedef {Object} ImageElement
 * @property {number} tagID
 * @property {number} length
 * @property {Uint8Array | undefined} tagMeta
 * @property {Uint8Array} data
 *
 * @typedef {Object} ParsedImage
 * @property {ImageHeader} header
 * @property {ImageElement[]} elements
 * @property {ArrayBuffer} raw
 * @property {string} stack
 *
 * @typedef {Object} IndexMetadata
 * @property {string} fileName
 * @property {number} fileVersion
 * @property {number} fileSize
 * @property {string} url
 * @property {number} imageType
 * @property {number} manufacturerCode
 * @property {string} sha512
 * @property {string} otaHeaderString
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8");
const UPGRADE_FILE_IDENTIFIER = new Uint8Array([0x1e, 0xf1, 0xee, 0x0b]);
const OTA_HEADER_MIN_LENGTH = 56;
/** @type {Record<number, string>} */
const ZIGBEE_SPEC_TAGS = {
    0: "Upgrade Image",
    1: "ECDSA Signature (Crypto Suite 1)",
    2: "ECDSA Signing Certificate (Crypto Suite 1)",
    3: "Image Integrity Code",
    4: "Picture Data",
    5: "ECDSA Signature (Crypto Suite 2)",
    6: "ECDSA Signing Certificate (Crypto Suite 2)",
    // 0xf000 – 0xffff Manufacturer Specific Use
};
const TELINK_AES_TAG_ID = 0xf000;
const PROTECTION_TAG_IDS = new Set([0x0001, 0x0002, 0x0003, 0x0005, 0x0006, TELINK_AES_TAG_ID]);

const SI_GBL_HEADER_TAG = 0xeb17a603;
const SI_EBL_TAG_HEADER = 0x0;
const SI_EBL_IMAGE_SIGNATURE = 0xe350;
const SI_EBL_TAG_ENC_HEADER = 0xfb05;

const TI_OAD_IMG_ID_VAL_CC26X2R1_BYTES = textEncoder.encode("CC26x2R1");
const TI_OAD_IMG_ID_VAL_CC13X2R1_BYTES = textEncoder.encode("CC13x2R1");
const TI_OAD_IMG_ID_VAL_CC13X4_BYTES = textEncoder.encode("CC13x4  ");
const TI_OAD_IMG_ID_VAL_CC26X3_BYTES = textEncoder.encode("CC26x3  ");
const TI_OAD_IMG_ID_VAL_CC26X4_BYTES = textEncoder.encode("CC26x4  ");
const TI_OAD_IMG_ID_VAL_OADIMG_BYTES = textEncoder.encode("OAD IMG ");
const TI_OAD_IMG_ID_VAL_CC23X0R2_BYTES = textEncoder.encode("CC23x0R2");
const TL_START_UP_FLAG_BYTES = textEncoder.encode("KNLT");
const TL_SR_TAG_BYTES = textEncoder.encode("TLSR");
const ZBOSS_MARKERS = [textEncoder.encode("nRF"), textEncoder.encode("nrf5"), textEncoder.encode("nrf_")];

/** @type {HTMLInputElement} */
const fileInput = getEl("file-input");
/** @type {HTMLButtonElement} */
const downloadBtn = getEl("download-btn");
/** @type {HTMLButtonElement} */
const resetBtn = getEl("reset-btn");
/** @type {HTMLFormElement} */
const headerForm = getEl("header-form");
/** @type {HTMLDivElement} */
const metadataBox = getEl("metadata");
/** @type {HTMLTextAreaElement} */
const indexJson = getEl("index-json");
/** @type {HTMLSpanElement} */
const statusEl = getEl("status");
/** @type {NodeListOf<HTMLInputElement>} */
const fileVersionModeInputs = document.querySelectorAll('input[name="fileVersionMode"]');
/** @type {HTMLInputElement} */
const fileVersionAppRelease = getEl("fileVersionAppRelease");
/** @type {HTMLInputElement} */
const fileVersionAppBuild = getEl("fileVersionAppBuild");
/** @type {HTMLInputElement} */
const fileVersionStackRelease = getEl("fileVersionStackRelease");
/** @type {HTMLInputElement} */
const fileVersionStackBuild = getEl("fileVersionStackBuild");
/** @type {HTMLDivElement} */
const fileVersionHint = getEl("fileVersionHint");
/** @type {HTMLDivElement} */
const fileVersionNumberRow = getEl("fileVersionNumberRow");
/** @type {HTMLDivElement} */
const fileVersionZigbeeRow = getEl("fileVersionZigbeeRow");
/** @type {HTMLDivElement} */
const protectionWarning = getEl("protection-warning");
/** @type {HTMLParagraphElement} */
const protectionWarningBody = getEl("protection-warning-body");

/** @type {{fileName: string, parsed: ParsedImage | null}} */
const state = { fileName: "ota.bin", parsed: null };
/** @type {number | null} */
let indexRefreshHandle = null;

// Wire up UI handlers.
fileInput.addEventListener("change", async (event) => {
    const target = /** @type {HTMLInputElement} */ (event.target);
    const file = target.files?.[0];

    if (!file) {
        return;
    }

    state.fileName = file.name || "ota.bin";

    setStatus(`Reading ${state.fileName} ...`);

    try {
        const buffer = await readFileAsArrayBuffer(file);
        const parsed = parseImage(buffer);
        state.parsed = parsed;

        renderProtectionWarning(parsed.elements);
        populateForm();
        renderMetadata();
        await refreshIndexMetadata();
        setStatus(`Loaded ${state.fileName}`);

        downloadBtn.disabled = false;
        resetBtn.disabled = false;
    } catch (error) {
        console.error(error);
        setStatus("Failed to read file. Check console for details.");
    }
});

downloadBtn.addEventListener("click", async () => {
    if (!state.parsed) {
        return;
    }

    try {
        const updatedHeader = collectHeaderFromForm();
        const normalized = normalizeHeader(updatedHeader, state.parsed.raw);
        const rebuilt = serializeImage(normalized, state.parsed.raw);
        state.parsed = { ...state.parsed, header: normalized, raw: rebuilt };

        populateForm();
        renderMetadata();
        await refreshIndexMetadata();
        triggerDownload(rebuilt, state.fileName);
        setStatus("Rebuilt file ready.");
    } catch (error) {
        console.error(error);
        setStatus("Failed to rebuild file.");
    }
});

resetBtn.addEventListener("click", async () => {
    if (!state.parsed) {
        return;
    }

    populateForm();
    renderMetadata();
    await refreshIndexMetadata();

    setStatus("Reset to parsed values.");
});

headerForm.addEventListener("input", () => {
    if (!state.parsed) {
        return;
    }

    const draft = collectHeaderFromForm();
    const normalized = normalizeHeader(draft, state.parsed.raw);

    getInputEl("otaHeaderLength").value = String(normalized.otaHeaderLength);
    getInputEl("otaHeaderFieldControl").value = String(normalized.otaHeaderFieldControl);

    scheduleIndexRefresh();
});

fileVersionModeInputs.forEach((input) => {
    input.addEventListener("change", () => {
        const mode = getVersionMode();

        syncVersionUI(mode);
        scheduleIndexRefresh();
    });
});

getInputEl("fileVersion").addEventListener("input", () => {
    const num = Number(getInputEl("fileVersion").value || 0);

    setSegmentsFromVersion(Number.isNaN(num) ? 0 : num);
});

[fileVersionAppRelease, fileVersionAppBuild, fileVersionStackRelease, fileVersionStackBuild].forEach((el) => {
    el.addEventListener("input", () => {
        syncSegmentsToNumber();
        scheduleIndexRefresh();
    });
});

function scheduleIndexRefresh() {
    if (indexRefreshHandle) {
        clearTimeout(indexRefreshHandle);
    }

    indexRefreshHandle = window.setTimeout(async () => {
        indexRefreshHandle = null;
        await refreshIndexMetadata();
    }, 200);
}

async function refreshIndexMetadata() {
    if (!state.parsed) {
        indexJson.value = "";

        return;
    }

    const normalizedHeader = normalizeHeader(collectHeaderFromForm(), state.parsed.raw);
    const rebuilt = serializeImage(normalizedHeader, state.parsed.raw);

    try {
        const metadata = await buildIndexMetadata({
            header: normalizedHeader,
            raw: rebuilt,
            elements: state.parsed.elements,
            stack: state.parsed.stack,
        });
        indexJson.value = JSON.stringify(metadata, null, 2);
    } catch (error) {
        console.error(error);
        setStatus("Failed to build index metadata.");

        indexJson.value = "";
    }
}

/**
 * Read a File into an ArrayBuffer.
 * @param {File} file
 * @returns {Promise<ArrayBuffer>}
 */
function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            if (reader.result instanceof ArrayBuffer) {
                resolve(reader.result);
            } else {
                reject(new Error("Unexpected read result."));
            }
        };
        reader.onerror = () => reject(reader.error ?? new Error("Unknown file read error."));

        reader.readAsArrayBuffer(file);
    });
}

/**
 * Try to identify the Zigbee stack from a raw OTA image.
 * @param {ImageElement[]} elements
 * @returns {string}
 */
function identifyImageZigbeeStack(elements) {
    if (!elements.length) {
        return "Unknown";
    }

    for (const element of elements) {
        const bytes = element.data;
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

        if (element.tagID === TELINK_AES_TAG_ID) {
            return "Telink (Encrypted)";
        }

        if (bytes.length >= 4 && view.getUint32(0, false) === SI_GBL_HEADER_TAG) {
            return "EmberZNet (GBL)";
        }

        if (bytes.length >= 8 && view.getUint16(0, false) === SI_EBL_TAG_HEADER && view.getUint16(6, false) === SI_EBL_IMAGE_SIGNATURE) {
            return "EmberZNet (EBL)";
        }

        if (bytes.length >= 2 && view.getUint16(0, false) === SI_EBL_TAG_ENC_HEADER) {
            return "EmberZNet (EBL ENC)";
        }

        if (bytesStartsWith(bytes, TI_OAD_IMG_ID_VAL_CC26X2R1_BYTES)) {
            return "zStack (CC26x2R1)";
        }

        if (bytesStartsWith(bytes, TI_OAD_IMG_ID_VAL_CC13X2R1_BYTES)) {
            return "zStack (CC13x2R1)";
        }

        if (bytesStartsWith(bytes, TI_OAD_IMG_ID_VAL_CC13X4_BYTES)) {
            return "zStack (CC13x4)";
        }

        if (bytesStartsWith(bytes, TI_OAD_IMG_ID_VAL_CC26X3_BYTES)) {
            return "zStack (CC26x3)";
        }

        if (bytesStartsWith(bytes, TI_OAD_IMG_ID_VAL_CC26X4_BYTES)) {
            return "zStack (CC26x4)";
        }

        if (bytesStartsWith(bytes, TI_OAD_IMG_ID_VAL_OADIMG_BYTES)) {
            return "zStack (OAD IMG)";
        }

        if (bytesStartsWith(bytes, TI_OAD_IMG_ID_VAL_CC23X0R2_BYTES)) {
            return "zStack (CC23x0R2)";
        }

        if (bytesEqualsAt(bytes, TL_START_UP_FLAG_BYTES, 8)) {
            const tlsrIndex = findSubarray(bytes, TL_SR_TAG_BYTES);

            if (tlsrIndex !== -1) {
                const decoded = textDecoder.decode(bytes.slice(tlsrIndex, Math.min(bytes.length, tlsrIndex + 8))).trim();
                return `Telink (${decoded})`;
            }

            return "Telink";
        }

        if (ZBOSS_MARKERS.some((marker) => findSubarray(bytes, marker) !== -1)) {
            return "ZBOSS (Nordic - fuzzy matching)";
        }
    }

    return "Unknown";
}

/**
 * Detect whether the image elements contain protection/signature/encryption tags.
 * @param {ImageElement[]} elements
 * @returns {number[]}
 */
function detectProtectionTags(elements) {
    /** @type {number[]} */
    const matched = [];

    for (const element of elements) {
        if (PROTECTION_TAG_IDS.has(element.tagID) && !matched.includes(element.tagID)) {
            matched.push(element.tagID);
        }
    }

    return matched;
}

/**
 * Show or hide the protection warning banner.
 * @param {ImageElement[]} elements
 */
function renderProtectionWarning(elements) {
    const tags = detectProtectionTags(elements);

    if (!tags.length) {
        protectionWarning.classList.add("hidden");
        return;
    }

    const readableTags = tags.map((tag) => {
        if (tag === TELINK_AES_TAG_ID) {
            return "Telink AES encryption (0xf000)";
        }

        const label = ZIGBEE_SPEC_TAGS[tag] ?? "Protected tag";

        return `${label} (${formatTagId(tag)})`;
    });

    protectionWarningBody.textContent = `This image includes signature, integrity, or encryption data: ${readableTags.join(", ")}. Editing header fields may invalidate these checks and the device could reject the image.`;
    protectionWarning.classList.remove("hidden");
}

/**
 * Parse a raw OTA image.
 * @param {ArrayBuffer} buffer
 * @returns {ParsedImage}
 */
function parseImage(buffer) {
    // find the actual start of OTA data (might have padding before/after)
    const otaStartIndex = findSubarray(new Uint8Array(buffer), UPGRADE_FILE_IDENTIFIER);
    assert(otaStartIndex !== -1, "Invalid OTA file");

    // slice buffer from the OTA start if there's padding
    const otaBuffer = otaStartIndex > 0 ? buffer.slice(otaStartIndex) : buffer;
    const header = parseImageHeader(otaBuffer);
    const elements = parseElements(otaBuffer, header);
    const raw = otaBuffer.slice(0, header.totalImageSize);
    const stack = identifyImageZigbeeStack(elements);

    return { header, elements, raw, stack };
}

/**
 * Parse only the header portion of the image.
 * @param {ArrayBuffer} buffer
 * @returns {ImageHeader}
 */
function parseImageHeader(buffer) {
    const view = new DataView(buffer);
    assert(buffer.byteLength >= OTA_HEADER_MIN_LENGTH, "Buffer too small to contain header");

    const otaUpgradeFileIdentifier = new Uint8Array(buffer.slice(0, 4));
    const otaHeaderVersion = view.getUint16(4, true);
    const otaHeaderLength = view.getUint16(6, true);
    const otaHeaderFieldControl = view.getUint16(8, true);
    const manufacturerCode = view.getUint16(10, true);
    const imageType = view.getUint16(12, true);
    const fileVersion = view.getUint32(14, true);
    const zigbeeStackVersion = view.getUint16(18, true);
    const otaHeaderString = decodeFixedString(buffer, 20, 52);
    const totalImageSize = view.getUint32(52, true);

    let headerPos = OTA_HEADER_MIN_LENGTH;
    /** @type {number | undefined} */
    let securityCredentialVersion;
    /** @type {Uint8Array<ArrayBuffer> | undefined} */
    let upgradeFileDestination;
    /** @type {number | undefined} */
    let minimumHardwareVersion;
    /** @type {number | undefined} */
    let maximumHardwareVersion;

    if (otaHeaderFieldControl & 0x0001) {
        assert(headerPos + 1 <= buffer.byteLength, "Unexpected end of buffer while reading securityCredentialVersion");

        securityCredentialVersion = view.getUint8(headerPos);
        headerPos += 1;
    }

    if (otaHeaderFieldControl & 0x0002) {
        assert(headerPos + 8 <= buffer.byteLength, "Unexpected end of buffer while reading upgradeFileDestination");

        upgradeFileDestination = new Uint8Array(buffer.slice(headerPos, headerPos + 8));
        headerPos += 8;
    }

    if (otaHeaderFieldControl & 0x0004) {
        assert(headerPos + 4 <= buffer.byteLength, "Unexpected end of buffer while reading hardware versions");

        minimumHardwareVersion = view.getUint16(headerPos, true);
        maximumHardwareVersion = view.getUint16(headerPos + 2, true);
    }

    return {
        otaUpgradeFileIdentifier,
        otaHeaderVersion,
        otaHeaderLength,
        otaHeaderFieldControl,
        manufacturerCode,
        imageType,
        fileVersion,
        zigbeeStackVersion,
        otaHeaderString,
        totalImageSize,
        securityCredentialVersion,
        upgradeFileDestination,
        minimumHardwareVersion,
        maximumHardwareVersion,
    };
}

/**
 * Parse image elements following the header.
 * @param {ArrayBuffer} buffer
 * @param {ImageHeader} header
 * @returns {ImageElement[]}
 */
function parseElements(buffer, header) {
    const bytes = new Uint8Array(buffer);
    const elements = [];
    let position = header.otaHeaderLength;
    const limit = Math.min(header.totalImageSize, bytes.length);

    while (position + 6 <= limit) {
        const [element, elementOffset] = parseSubElement(bytes, position);

        elements.push(element);

        position += element.length + elementOffset;
    }

    return elements;
}

/**
 * Parse a single OTA element.
 * @param {Uint8Array} bytes
 * @param {number} position
 * @returns {[ImageElement, number]}
 */
function parseSubElement(bytes, position) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const tagID = view.getUint16(position, true);
    const length = view.getUint32(position + 2, true);

    if (tagID === TELINK_AES_TAG_ID) {
        // OTA_FLAG_IMAGE_ELEM_INFO1 (1-byte) + OTA_FLAG_IMAGE_ELEM_INFO2 (1-byte)
        const tagMeta = bytes.slice(position + 6, position + 8);
        const data = bytes.slice(position + 8, position + 8 + length);

        return [{ tagID, length, tagMeta, data }, 8];
    }

    const data = bytes.slice(position + 6, position + 6 + length);

    return [{ tagID, length, tagMeta: undefined, data }, 6];
}

/**
 * Generate index metadata for the image.
 * @param {ParsedImage} image
 * @returns {Promise<IndexMetadata>}
 */
async function buildIndexMetadata(image) {
    const sha512 = await computeSHA512(image.raw);

    return {
        fileName: state.fileName,
        fileVersion: image.header.fileVersion,
        fileSize: image.header.totalImageSize,
        url: `./${state.fileName}`,
        imageType: image.header.imageType,
        manufacturerCode: image.header.manufacturerCode,
        sha512,
        otaHeaderString: image.header.otaHeaderString.replaceAll("\u0000", ""),
    };
}

/**
 * Compute SHA-512 hex string for an ArrayBuffer using Web Crypto.
 * @param {ArrayBuffer} buffer
 * @returns {Promise<string>}
 */
async function computeSHA512(buffer) {
    if (!crypto?.subtle) {
        throw new Error("Web Crypto API not available");
    }

    const hashBuffer = await crypto.subtle.digest("SHA-512", buffer);

    return arrayBufferToHex(hashBuffer);
}

/**
 * Convert ArrayBuffer to hex string.
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function arrayBufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);

    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

/**
 * Normalize header fields that must be auto-computed.
 * @param {ImageHeader} header
 * @param {ArrayBuffer} raw
 * @returns {ImageHeader}
 */
function normalizeHeader(header, raw) {
    const rawLength = raw.byteLength;
    const sanitizedHeaderString = header.otaHeaderString.slice(0, 32);
    const totalImageSize = clamp(header.totalImageSize || rawLength, OTA_HEADER_MIN_LENGTH, rawLength);
    const hasSecurity = header.securityCredentialVersion !== undefined;
    const upgradeFileDestination =
        header.upgradeFileDestination && header.upgradeFileDestination.length > 0 ? header.upgradeFileDestination : undefined;
    const hasUpgrade = !!upgradeFileDestination;

    if (upgradeFileDestination) {
        assert(upgradeFileDestination.length === 8, "upgradeFileDestination must be 8 bytes");
    }

    const hasHwRange = header.minimumHardwareVersion !== undefined && header.maximumHardwareVersion !== undefined;

    let otaHeaderFieldControl = 0;
    let otaHeaderLength = OTA_HEADER_MIN_LENGTH;

    if (hasSecurity) {
        otaHeaderFieldControl |= 0x0001;
        otaHeaderLength += 1;
    }

    if (hasUpgrade) {
        otaHeaderFieldControl |= 0x0002;
        otaHeaderLength += 8;
    }

    if (hasHwRange) {
        otaHeaderFieldControl |= 0x0004;
        otaHeaderLength += 4;
    }

    return {
        ...header,
        otaUpgradeFileIdentifier: header.otaUpgradeFileIdentifier || UPGRADE_FILE_IDENTIFIER,
        otaHeaderVersion: header.otaHeaderVersion || 0x0100,
        otaHeaderLength,
        otaHeaderFieldControl,
        otaHeaderString: sanitizedHeaderString,
        totalImageSize,
        securityCredentialVersion: hasSecurity ? header.securityCredentialVersion : undefined,
        upgradeFileDestination: hasUpgrade ? upgradeFileDestination : undefined,
        minimumHardwareVersion: hasHwRange ? header.minimumHardwareVersion : undefined,
        maximumHardwareVersion: hasHwRange ? header.maximumHardwareVersion : undefined,
    };
}

/**
 * Convert a numeric fileVersion into Zigbee release/build segments.
 * @param {number} version
 * @returns {{appRelease: string, appBuild: number, stackRelease: string, stackBuild: number}}
 */
function fileVersionToSegments(version) {
    const unsigned = Number(version) >>> 0;
    const versionString = unsigned.toString(16).padStart(8, "0");
    const appRelease = `${versionString[0]}.${versionString[1]}`;
    const appBuild = Number.parseInt(versionString.slice(2, 4), 16);
    const stackRelease = `${versionString[4]}.${versionString[5]}`;
    const stackBuild = Number.parseInt(versionString.slice(6), 16);

    return { appRelease, appBuild, stackRelease, stackBuild };
}

/**
 * Build a numeric version from Zigbee release/build segments.
 * @param {string} appRelease
 * @param {string} appBuild
 * @param {string} stackRelease
 * @param {string} stackBuild
 * @returns {number}
 */
function segmentsToVersion(appRelease, appBuild, stackRelease, stackBuild) {
    const appRelMatch = appRelease.match(/^([0-9A-Fa-f])\.([0-9A-Fa-f])$/);
    const stackRelMatch = stackRelease.match(/^([0-9A-Fa-f])\.([0-9A-Fa-f])$/);

    if (!appRelMatch || !stackRelMatch) {
        return Number.NaN;
    }

    const appBuildNum = Number(appBuild);
    const stackBuildNum = Number(stackBuild);

    if (Number.isNaN(appBuildNum) || Number.isNaN(stackBuildNum)) {
        return Number.NaN;
    }

    if (appBuildNum < 0 || appBuildNum > 255 || stackBuildNum < 0 || stackBuildNum > 255) {
        return Number.NaN;
    }

    const versionString = `${appRelMatch[1]}${appRelMatch[2]}${appBuildNum.toString(16).padStart(2, "0")}${stackRelMatch[1]}${stackRelMatch[2]}${stackBuildNum.toString(16).padStart(2, "0")}`;

    return Number.parseInt(versionString, 16);
}

/**
 * Human-friendly descriptor for file version.
 * @param {number} version
 * @returns {string}
 */
function formatVersionDescriptor(version) {
    const seg = fileVersionToSegments(version);

    return `App ${seg.appRelease} build ${seg.appBuild} | Stack ${seg.stackRelease} build ${seg.stackBuild}`;
}

/**
 * Get the currently selected version input mode.
 * @returns {"number" | "zigbee"}
 */
function getVersionMode() {
    const checked = Array.from(fileVersionModeInputs).find((input) => input.checked);

    return checked?.value === "zigbee" ? "zigbee" : "number";
}

/**
 * Populate segment inputs from a numeric version.
 * @param {number} version
 */
function setSegmentsFromVersion(version) {
    const seg = fileVersionToSegments(version);
    fileVersionAppRelease.value = seg.appRelease;
    fileVersionAppBuild.value = String(seg.appBuild);
    fileVersionStackRelease.value = seg.stackRelease;
    fileVersionStackBuild.value = String(seg.stackBuild);

    updateVersionHint(version);
}

/**
 * Update hint text for the current version number.
 * @param {number} version
 */
function updateVersionHint(version) {
    fileVersionHint.textContent = formatVersionDescriptor(version);
}

/**
 * When editing segments, sync back to numeric field and hint.
 */
function syncSegmentsToNumber() {
    const derived = segmentsToVersion(
        fileVersionAppRelease.value,
        fileVersionAppBuild.value,
        fileVersionStackRelease.value,
        fileVersionStackBuild.value,
    );

    if (!Number.isNaN(derived)) {
        getInputEl("fileVersion").value = String(derived);

        updateVersionHint(derived);
    } else {
        fileVersionHint.textContent = "Enter app/stack release (A.B) and builds (0-255)";
    }
}

/**
 * Toggle visibility and keep fields in sync for the chosen version mode.
 * @param {"number" | "zigbee"} mode
 */
function syncVersionUI(mode) {
    if (mode === "zigbee") {
        fileVersionNumberRow.classList.add("hidden");
        fileVersionZigbeeRow.classList.remove("hidden");

        const numeric = Number(getInputEl("fileVersion").value || 0);

        setSegmentsFromVersion(Number.isNaN(numeric) ? 0 : numeric);
    } else {
        fileVersionNumberRow.classList.remove("hidden");
        fileVersionZigbeeRow.classList.add("hidden");

        const numeric = Number(getInputEl("fileVersion").value || 0);

        if (!Number.isNaN(numeric)) {
            updateVersionHint(numeric);
        } else {
            fileVersionHint.textContent = "Enter file version";
        }
    }
}

/**
 * Create a new binary with updated header data.
 * @param {ImageHeader} header
 * @param {ArrayBuffer} original
 * @returns {ArrayBuffer}
 */
function serializeImage(header, original) {
    const normalized = normalizeHeader(header, original);
    const output = new Uint8Array(normalized.totalImageSize);
    const source = new Uint8Array(original);
    output.set(source.subarray(0, output.length));

    const view = new DataView(output.buffer);

    output.set(normalized.otaUpgradeFileIdentifier.slice(0, 4), 0);
    view.setUint16(4, normalized.otaHeaderVersion, true);
    view.setUint16(6, normalized.otaHeaderLength, true);
    view.setUint16(8, normalized.otaHeaderFieldControl, true);
    view.setUint16(10, normalized.manufacturerCode, true);
    view.setUint16(12, normalized.imageType, true);
    view.setUint32(14, normalized.fileVersion, true);
    view.setUint16(18, normalized.zigbeeStackVersion, true);

    const headerStringBytes = textEncoder.encode(normalized.otaHeaderString);
    const paddedHeaderString = new Uint8Array(32);

    paddedHeaderString.set(headerStringBytes.subarray(0, 32));
    output.set(paddedHeaderString, 20);

    view.setUint32(52, normalized.totalImageSize, true);

    let headerPos = OTA_HEADER_MIN_LENGTH;

    if (normalized.otaHeaderFieldControl & 0x0001) {
        view.setUint8(headerPos, normalized.securityCredentialVersion ?? 0);

        headerPos += 1;
    }

    if (normalized.otaHeaderFieldControl & 0x0002) {
        output.set(normalized.upgradeFileDestination ?? new Uint8Array(8), headerPos);

        headerPos += 8;
    }

    if (normalized.otaHeaderFieldControl & 0x0004) {
        view.setUint16(headerPos, normalized.minimumHardwareVersion ?? 0, true);
        view.setUint16(headerPos + 2, normalized.maximumHardwareVersion ?? 0, true);
    }

    return output.buffer;
}

/**
 * Render header data into the editable form.
 */
function populateForm() {
    if (!state.parsed) {
        return;
    }

    const { header } = state.parsed;

    getInputEl("otaUpgradeFileIdentifier").value = formatHex(header.otaUpgradeFileIdentifier);
    getInputEl("otaHeaderVersion").value = String(header.otaHeaderVersion);
    getInputEl("otaHeaderLength").value = String(header.otaHeaderLength);
    getInputEl("otaHeaderFieldControl").value = String(header.otaHeaderFieldControl);
    getInputEl("manufacturerCode").value = String(header.manufacturerCode);
    getInputEl("imageType").value = String(header.imageType);
    getInputEl("fileVersion").value = String(header.fileVersion);

    setSegmentsFromVersion(header.fileVersion);
    updateVersionHint(header.fileVersion);
    syncVersionUI(getVersionMode());

    getInputEl("zigbeeStackVersion").value = String(header.zigbeeStackVersion);
    getInputEl("otaHeaderString").value = header.otaHeaderString;
    getInputEl("totalImageSize").value = String(header.totalImageSize);
    getInputEl("securityCredentialVersion").value = header.securityCredentialVersion === undefined ? "" : String(header.securityCredentialVersion);
    getInputEl("upgradeFileDestination").value = header.upgradeFileDestination ? formatHex(header.upgradeFileDestination) : "";
    getInputEl("minimumHardwareVersion").value = header.minimumHardwareVersion === undefined ? "" : String(header.minimumHardwareVersion);
    getInputEl("maximumHardwareVersion").value = header.maximumHardwareVersion === undefined ? "" : String(header.maximumHardwareVersion);
}

/**
 * Collect header values from the form, respecting read-only fields from the parsed data.
 * @returns {ImageHeader}
 */
function collectHeaderFromForm() {
    if (!state.parsed) {
        throw new Error("Invalid state, no parsed data found");
    }

    const { header } = state.parsed;
    /** @type {(id: string) => HTMLInputElement} */
    const el = (id) => getEl(id);
    const toNumber = /** @param {string} value */ (value) => Number(value || 0);
    const toOptionalNumber = /** @param {string} value */ (value) => (value === "" ? undefined : Number(value));
    const mode = getVersionMode();
    let fileVersion = toNumber(el("fileVersion").value);

    if (mode === "zigbee") {
        const derived = segmentsToVersion(
            fileVersionAppRelease.value,
            fileVersionAppBuild.value,
            fileVersionStackRelease.value,
            fileVersionStackBuild.value,
        );

        if (!Number.isNaN(derived)) {
            fileVersion = derived;
        }
    }

    return {
        otaUpgradeFileIdentifier: header.otaUpgradeFileIdentifier,
        otaHeaderVersion: header.otaHeaderVersion,
        otaHeaderLength: header.otaHeaderLength,
        otaHeaderFieldControl: header.otaHeaderFieldControl,
        manufacturerCode: toNumber(el("manufacturerCode").value),
        imageType: toNumber(el("imageType").value),
        fileVersion,
        zigbeeStackVersion: toNumber(el("zigbeeStackVersion").value),
        otaHeaderString: el("otaHeaderString").value,
        totalImageSize: toNumber(el("totalImageSize").value),
        securityCredentialVersion: toOptionalNumber(el("securityCredentialVersion").value),
        upgradeFileDestination: parseHexInput(el("upgradeFileDestination").value),
        minimumHardwareVersion: toOptionalNumber(el("minimumHardwareVersion").value),
        maximumHardwareVersion: toOptionalNumber(el("maximumHardwareVersion").value),
    };
}

/**
 * Render a read-only metadata block.
 */
function renderMetadata() {
    if (!state.parsed) {
        return;
    }

    const { header, elements, stack } = state.parsed;

    let content = `Identifier, ${formatHex(header.otaUpgradeFileIdentifier)}
Header version: ${header.otaHeaderVersion}
Header length: ${header.otaHeaderLength}
Field control: ${header.otaHeaderFieldControl}
Manufacturer code: ${header.manufacturerCode}
Image type: ${header.imageType}
File version: ${`${header.fileVersion} (${formatVersionDescriptor(header.fileVersion)})`}
Zigbee stack version: ${header.zigbeeStackVersion}
Header string: ${header.otaHeaderString}
Total image size: ${header.totalImageSize}
Security credential version: ${header.securityCredentialVersion ?? "—"}
Upgrade file destination: ${header.upgradeFileDestination ? formatHex(header.upgradeFileDestination) : "—"}
Min hardware version: ${header.minimumHardwareVersion ?? "—"}
Max hardware version: ${header.maximumHardwareVersion ?? "—"}
Identified stack: ${stack ?? "—"}
Tags:`;

    for (const { tagID, length } of elements) {
        content += `\n  - [${formatTagId(tagID)}] ${tagID >= 0xf000 ? "Manufacturer-specific" : (ZIGBEE_SPEC_TAGS[tagID] ?? "Unknown")} (length: ${length})`;
    }

    metadataBox.textContent = content;
}

/**
 * Trigger browser download for the rebuilt image.
 * @param {ArrayBuffer} buffer
 * @param {string} fileName
 */
function triggerDownload(buffer, fileName) {
    const blob = new Blob([buffer], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName || "ota.bin";

    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Format an OTA tag identifier as hex.
 * @param {number} tagId
 * @returns {string}
 */
function formatTagId(tagId) {
    return `0x${tagId.toString(16).padStart(4, "0")}`;
}

/**
 * Convert bytes to spaced hex string.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function formatHex(bytes) {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
}

/**
 * Parse a hex string into bytes.
 * @param {string} value
 * @returns {Uint8Array | undefined}
 */
function parseHexInput(value) {
    const clean = value.trim();

    if (!clean) {
        return undefined;
    }

    const parts = clean.split(/\s+/).filter(Boolean);
    const bytes = parts.map((p) => Number.parseInt(p, 16)).filter((n) => !Number.isNaN(n));

    return bytes.length ? new Uint8Array(bytes) : undefined;
}

/**
 * Update footer status text.
 * @param {string} message
 */
function setStatus(message) {
    statusEl.textContent = message;
}

/**
 * Decode a fixed-width UTF-8 string, trimming null bytes.
 * @param {ArrayBuffer | Uint8Array} buffer
 * @param {number} start
 * @param {number} end
 * @returns {string}
 */
function decodeFixedString(buffer, start, end) {
    const source = buffer instanceof ArrayBuffer ? buffer : buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
    const slice = source.slice(start, end);

    return textDecoder.decode(slice).replace(/\0+$/g, "").trimEnd();
}

/**
 * Clamp a numeric value between min and max.
 * @param {number} value
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function clamp(value, min, max) {
    return Math.min(Math.max(value, min), max);
}

/**
 * Throw if condition is false.
 * @param {boolean} condition
 * @param {string} message
 */
function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

/**
 * Safe element getter.
 * @template {HTMLElement} T
 * @param {string} id
 * @returns {T}
 */
function getEl(id) {
    const el = document.querySelector(`#${id}`);

    if (!el) {
        throw new Error(`Missing element #${id}`);
    }

    return /** @type {T} */ (el);
}

/**
 * Safe input element getter.
 * @template {HTMLInputElement} T
 * @param {string} id
 * @returns {T}
 */
function getInputEl(id) {
    return getEl(id);
}

/**
 * Check if a byte buffer starts with a prefix.
 * @param {Uint8Array} haystack
 * @param {Uint8Array} needle
 */
function bytesStartsWith(haystack, needle) {
    if (needle.length > haystack.length) {
        return false;
    }

    for (let i = 0; i < needle.length; i += 1) {
        if (haystack[i] !== needle[i]) {
            return false;
        }
    }

    return true;
}

/**
 * Find a subarray inside a byte buffer.
 * @param {Uint8Array} haystack
 * @param {Uint8Array} needle
 * @returns {number}
 */
function findSubarray(haystack, needle) {
    if (!needle.length) {
        return 0;
    }

    for (let i = 0; i <= haystack.length - needle.length; i += 1) {
        if (bytesEqualsAt(haystack, needle, i)) {
            return i;
        }
    }

    return -1;
}

/**
 * Compare a segment of a haystack with a needle.
 * @param {Uint8Array} haystack
 * @param {Uint8Array} needle
 * @param {number} offset
 */
function bytesEqualsAt(haystack, needle, offset) {
    if (offset < 0 || offset + needle.length > haystack.length) {
        return false;
    }

    for (let i = 0; i < needle.length; i += 1) {
        if (haystack[offset + i] !== needle[i]) {
            return false;
        }
    }

    return true;
}

// Initialize placeholders.
syncVersionUI(getVersionMode());
setStatus("Waiting for file...");
