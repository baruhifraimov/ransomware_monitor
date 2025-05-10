"""
Configuration constants for the ransomware detection tool.
"""
import os

# Configuration settings for the ransomware monitor

# Directory to monitor
MONITOR_DIR = "./test"

# Log file settings
LOG_FILE = "ransomware_monitor.log"
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# File extensions to monitor closely
# Add extensions that are commonly used by ransomware or indicate encryption
ENCRYPTED_EXTENSIONS = [
    # Standard ransomware extensions
    ".enc", ".locked", ".crypto", ".crypt", ".crinf", ".r5a", ".XRNT", ".XTBL",
    ".RDM", ".RRK", ".encrypted", ". किला", ".AES", ".locky", ".zepto", ".odin",
    ".thor", ".cerber", ".ryk", ".wannacry", ".wncry", ".wcry", ".gavril",
    
    # Comprehensive list of .txt related encrypted extensions
    # .txt with appended extensions
    ".txt.enc", ".txt.locked", ".txt.crypto", ".txt.crypt", ".txt.crypted", 
    ".txt.encrypted", ".txt.coded", ".txt.ciphered", ".txt.aes", ".txt.lock",
    ".txt.key", ".txt.SecurIT", ".txt.cerber", ".txt.cerber2", ".txt.cerber3",
    ".txt.osiris", ".txt.mact", ".txt.zzzzz", ".txt.breaking_bad", ".txt.vault",
    ".txt.0x0", ".txt.726", ".txt.726.tmp", ".txt.axx", ".txt.damage", ".txt.ezz",
    ".txt.exx", ".txt.good", ".txt.hb15", ".txt.id-", ".txt.kraken", ".txt.kyra",
    ".txt.legion", ".txt.nochance", ".txt.venusf", ".txt.73i87A", ".txt.p5tkjw",
    ".txt.PEGS1", ".txt.MRCR1", ".txt.HA3", ".txt.zorro", ".txt.enigma",
    ".txt.vxLock", ".txt.killedXXX", ".txt.unavailable", ".txt.disappeared",
    ".txt.restored", ".txt.herbst", ".txt.sage", ".txt.globe", ".txt.WFLX",
    ".txt.cry", ".txt.wallet", ".txt.1999", ".txt.ransomed", ".txt.aesir",
    ".txt.encrypted_by", ".txt.encrypted-", ".txt.petya", ".txt.CrySiS",
    ".txt.DHARMA", ".txt.xtbl", ".txt.cryp1", ".txt.R4A", ".txt.R5A", ".txt.7z.encrypted",
    ".txt.zip.encrypted", ".txt.infected", ".txt.blocatto", ".txt.fantom",
    ".txt.kostya", ".txt.JUST", ".txt.raid", ".txt.DEUSCRYPT", ".txt.notforyou", 
    
    # Concatenated extensions (no dot)
    ".txtenc", ".txtlocked", ".txtcrypto", ".txtcrypt", ".txtcrypted", 
    ".txtencrypted", ".txtcoded", ".txtciphered", ".txtaes", ".txtlock",
    ".txtkey", ".txtcerber", ".txtosiris", ".txtzzzzz", ".txtbad", ".txtvault",
    ".txt0x0", ".txt726", ".txtaxx", ".txtdamage", ".txtezz", ".txtexx", ".txtgood",
    ".txthb15", ".txtid", ".txtkraken", ".txtkyra", ".txtlegion", ".txtnochance",
    ".txtvenus", ".txt73i87A", ".txtp5tkjw", ".txtPEGS1", ".txtMRCR1", ".txtHA3", 
    ".txtzorro", ".txtenigma", ".txtvxLock", ".txtkilled", ".txtunavailable", 
    ".txtdisappeared", ".txtrestored", ".txtherbst", ".txtsage", ".txtglobe", 
    ".txtWFLX", ".txtcry", ".txtwallet", ".txt1999", ".txtransomed", ".txtaesir",
    ".txtencryptedby", ".txtencrypted", ".txtpetya", ".txtCrySiS", ".txtwncry",
    ".txtDHARMA", ".txtxtbl", ".txtcryp1", ".txtR4A", ".txtR5A", ".txtinfected",
    ".txtblocatto", ".txtfantom", ".txtkostya", ".txtJUST", ".txtraid", 
    ".txtDEUSCRYPT", ".txtnotforyou", ".txtxxx",
    
    # Common TXT variations with known ransomware family extensions
    ".TXT.ID-*", ".txt.WALLET", ".txt.bip", ".txt.CRYPTOSHIELD", ".txt.POSHCODER",
    ".txt.BITSLOCKER", ".txt.KEYH0LES", ".txt.CRYPZ", ".txt.CRYP", ".txt.CRYPTON", 
    ".txt.NEMUCOD", ".txt.mafia", ".txt.coverton", ".txt.supersonic", ".txt.fragtor",
    ".txt.payms", ".txt.p0rt", ".txt.darkness", ".txt.lovewindows", ".txt.darkness",
    ".txt.gefickt", ".txt.cerberxxx", ".txt.paymedia", ".txt.duhust", ".txt.nobad",
    ".txt.rumblegoodbye", ".txt.payrmts", ".txt.stn", ".txt.serpent", ".txt.remind",
    ".txt.rip", ".txt.rgh", ".txt.btc", ".txt.crypto", ".txt.GEHENNA", ".txt.NSH0CK",
    ".txt.REVENGE", ".txt.EDR", ".txt.corona", ".txt.weapologize", ".txt.GOTHAM",
    ".txt.PHOENIX", ".txt.lockfile", ".txt.kencf", ".txt.deadfile", ".txt.odin", 
    ".txt.salsa", ".txt.FenixLocker", ".txt.KARMA", ".txt.atomy", ".txt.nuclear",
    ".txt.nuclear55",  ".txt.unlocker", ".txt.breaking_bad",
]

# Extensions of common document/data files to monitor for suspicious modifications/renames
TARGET_FILE_EXTENSIONS = [
    ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
    ".jpg", ".jpeg", ".png", ".zip", ".rar", ".sql", ".mdb", ".db", ".sqlite",
    ".csv", ".html", ".php", ".py", ".js", ".java", ".cpp", ".c"
]

# Thresholds for detection
# Entropy: Bits per byte. For an 8-bit byte, max entropy is 8.0.
# Files with entropy above this threshold might be considered encrypted.
# NDSS Symposium research: 7.0 bits/byte distinguishes between low and high entropy
HIGH_ENTROPY_THRESHOLD = 7.0

# Threshold for localized encryption detection using a sliding window approach
# Values exceeding 7.5 bits/byte in isolated windows are strong indicators of encryption
SLIDING_WINDOW_ENTROPY_THRESHOLD = 7.5

# Threshold for differential area analysis (comparing file entropy profile against random data)
# Values below 20 Bit-Bytes indicate encryption based on arXiv research
DIFFERENTIAL_AREA_THRESHOLD = 20

# Threshold for detecting significant file content changes (0.2 = 20%)
# Flag a file if more than this percentage of content changed in one modification
CHANGE_RATIO_THRESHOLD = 0.2

# Minimum file size in bytes to perform entropy analysis on (to avoid very small, potentially misleading files)
MIN_ENTROPY_FILE_SIZE_BYTES = 1024 # 1KB

# Burst detection / Statistical analysis thresholds
# Time window in seconds for burst detection (reduced from 60 seconds)
BURST_THRESHOLD_SECONDS = 10  # Time window in seconds

# Number of suspicious activities within the burst threshold time to trigger an alert
BURST_THRESHOLD_COUNT = 3  # Reduced from 5 since the time window is shorter

# File change rate thresholds (changed from per-minute to per-second)
# A human user typically performs 2-3 file operations per second at most during intensive work
# More than 5 operations per second indicates automated or suspicious activity

# Maximum file changes per second (reasonable threshold for human activity)
# A human can realistically modify/save about 1-2 files per second at most when working intensively
MAX_FILE_CHANGES_PER_SECOND = 3

# Maximum encryption-like changes per second
# Any encryption-like changes happening at a rate higher than 1 per second is suspicious
MAX_ENCRYPTION_LIKE_CHANGES_PER_SECOND = 1

# Time window for rate calculation (in seconds)
RATE_CALCULATION_WINDOW = 5  # Calculate rates over a 5-second rolling window

# Whitelist for paths or file patterns to ignore
PATH_WHITELIST = [
    "__pycache__/",
    ".git/",
    ".vscode/",
    "*.tmp", # Example temporary file pattern
]

# Settings for content analysis (future enhancement)
# RANSOM_NOTE_KEYWORDS = ["ransom", "decrypt", "bitcoin", "contact us", "your files are encrypted"]
# MAX_CONTENT_READ_SIZE_BYTES = 4096 # Max bytes to read from a file for content analysis
