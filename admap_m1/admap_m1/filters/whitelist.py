"""
Module   : admap_m1.filters.whitelist
Version  : 3.0.0
Dépend   : [re]

Filtrage des faux positifs (domaines bénins, modules système, sections binaires).
Contient les données de référence exhaustives (TLDs, patterns).
"""
from __future__ import annotations

import re
from typing import ClassVar


class WhitelistFilter:
    """Filtre statique pour éliminer les faux positifs fréquents.

    Contient des listes exhaustives de TLDs valides, domaines bénins,
    extensions de fichiers et patterns de modules système.
    """

    # Liste complète des TLDs valides (génériques, ccTLD, nouveaux gTLDs)
    VALID_TLDS: ClassVar[set[str]] = {
        # Generic TLDs
        "com", "org", "net", "edu", "gov", "mil", "int",
        # Country codes (IANA complet)
        "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as",
        "at", "au", "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh",
        "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bw", "by", "bz", "ca",
        "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "cr",
        "cu", "cv", "cw", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz",
        "ec", "ee", "eg", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo",
        "fr", "ga", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp",
        "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht",
        "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it", "je",
        "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw",
        "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv",
        "ly", "ma", "mc", "md", "me", "mg", "mh", "mk", "ml", "mm", "mn", "mo",
        "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na",
        "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om",
        "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt",
        "pw", "py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd",
        "se", "sg", "sh", "si", "sk", "sl", "sm", "sn", "so", "sr", "ss", "st",
        "sv", "sx", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj", "tk", "tl",
        "tm", "tn", "to", "tr", "tt", "tv", "tw", "tz", "ua", "ug", "uk", "us",
        "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws", "ye",
        "yt", "za", "zm", "zw",
        # New gTLDs et Sponsored
        "academy", "accountant", "accountants", "active", "actor", "adult",
        "aero", "agency", "airforce", "app", "army", "art", "asia", "associates",
        "attorney", "auction", "audio", "autos", "band", "bank", "bar", "bargains",
        "beer", "best", "bid", "bike", "bingo", "bio", "biz", "black", "blackfriday",
        "blog", "blue", "boutique", "build", "builders", "business", "buzz",
        "cab", "cafe", "cam", "camera", "camp", "capital", "cards", "care",
        "career", "careers", "cars", "case", "cash", "casino", "catering",
        "center", "ceo", "chat", "cheap", "church", "city", "claims", "cleaning",
        "click", "clinic", "clothing", "cloud", "club", "coach", "codes", "coffee",
        "college", "cologne", "community", "company", "computer", "condos",
        "construction", "consulting", "contact", "contractors", "cool", "coop",
        "corp", "country", "coupons", "credit", "creditcard", "cricket", "cruises",
        "dance", "date", "dating", "deals", "degree", "delivery", "democrat",
        "dental", "dentist", "design", "dev", "diamonds", "diet", "digital",
        "direct", "directory", "discount", "doctor", "dog", "domains", "download",
        "earth", "eco", "education", "email", "energy", "engineer", "engineering",
        "enterprises", "equipment", "estate", "events", "exchange", "expert",
        "exposed", "express", "fail", "faith", "family", "fan", "fans", "farm",
        "fashion", "finance", "financial", "fish", "fishing", "fit", "fitness",
        "flights", "florist", "flowers", "football", "forsale", "foundation",
        "fund", "furniture", "futbol", "fyi", "gallery", "game", "games",
        "garden", "gift", "gifts", "gives", "glass", "global", "gold", "golf",
        "graphics", "gratis", "green", "gripe", "group", "guide", "guitars",
        "guru", "haus", "health", "healthcare", "help", "here", "hiphop", "hiv",
        "hockey", "holdings", "holiday", "homes", "horse", "hospital", "host",
        "hosting", "house", "how", "ice", "icu", "immo", "immobilien", "industries",
        "info", "ink", "institute", "insure", "international", "investments",
        "irish", "jewelry", "jobs", "juegos", "kaufen", "kim", "kitchen", "kiwi",
        "land", "lawyer", "lease", "legal", "life", "lighting", "limited", "limo",
        "link", "live", "loan", "loans", "lol", "london", "love", "ltd", "luxury",
        "maison", "management", "market", "marketing", "markets", "media", "meet",
        "memorial", "men", "menu", "miami", "mobi", "moda", "moe", "mom", "money",
        "mortgage", "movie", "museum", "name", "navy", "network", "new", "news",
        "ngo", "ninja", "nyc", "one", "ong", "onl", "online", "ooo", "page",
        "paris", "partners", "parts", "party", "pharmacy", "photo", "photography",
        "photos", "physio", "pics", "pictures", "pink", "pizza", "place", "play",
        "plumbing", "plus", "poker", "porn", "post", "press", "pro", "productions",
        "prof", "properties", "property", "pub", "qpon", "racing", "recipes",
        "red", "rehab", "ren", "rent", "rentals", "repair", "report", "republican",
        "rest", "restaurant", "review", "reviews", "rich", "rip", "rocks", "rodeo",
        "run", "sale", "salon", "sarl", "school", "schule", "science", "services",
        "sex", "sexy", "shiksha", "shoes", "shop", "shopping", "show", "singles",
        "site", "ski", "soccer", "social", "software", "solar", "solutions",
        "soy", "space", "store", "studio", "study", "style", "sucks", "supplies",
        "supply", "support", "surf", "surgery", "systems", "tattoo", "tax",
        "taxi", "team", "tech", "technology", "tel", "tennis", "theater",
        "theatre", "tickets", "tienda", "tips", "tires", "today", "tokyo",
        "tools", "top", "tours", "town", "toys", "trade", "training", "travel",
        "tube", "university", "vacations", "vet", "viajes", "video", "villas",
        "vin", "vip", "vision", "vodka", "voting", "voyage", "wang", "watch",
        "webcam", "website", "wed", "wedding", "wiki", "win", "wine", "work",
        "works", "world", "wtf", "xxx", "xyz", "yoga", "zone",
        # Infrastructure
        "arpa"
    }

    # Domaines bénins (liste portée depuis extracteur.py + extensions)
    BENIGN_DOMAINS: ClassVar[set[str]] = {
        # Microsoft
        "microsoft.com", "windows.com", "windowsupdate.com", "microsoftonline.com",
        "office.com", "office365.com", "live.com", "hotmail.com", "outlook.com",
        "azure.com", "azureedge.net", "msn.com", "bing.com", "xbox.com",
        "visualstudio.com", "github.com", "githubusercontent.com", "nuget.org",
        # Google
        "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
        "googlesyndication.com", "googletagmanager.com", "googleadservices.com",
        "youtube.com", "ytimg.com", "googlevideo.com", "gmail.com",
        "android.com", "chromium.org", "goo.gl",
        # Amazon / AWS
        "amazon.com", "amazonaws.com", "awsstatic.com", "cloudfront.net",
        "amazonwebservices.com",
        # CDN / Infrastructure
        "cloudflare.com", "cloudflare.net", "akamai.net", "akamaiedge.net",
        "akamaized.net", "fastly.net", "fastlylb.net",
        "edgecastcdn.net", "llnwd.net", "footprint.net",
        # Apple
        "apple.com", "icloud.com", "mzstatic.com", "aaplimg.com",
        # Mozilla / Firefox
        "mozilla.org", "mozilla.com", "firefox.com",
        # Python / development
        "python.org", "pypi.org", "pythonhosted.org",
        # Linux / open source
        "ubuntu.com", "debian.org", "centos.org", "fedoraproject.org",
        "kernel.org", "gnu.org", "apache.org",
        # Security vendors (false positives communs)
        "symantec.com", "norton.com", "mcafee.com", "kaspersky.com",
        "virustotal.com", "misp-project.org",
        # Social / divers fréquents
        "facebook.com", "twitter.com", "linkedin.com", "instagram.com",
        "w3.org", "schema.org", "example.com", "example.org"
    }

    # Patterns de modules système
    SYSTEM_MODULE_PATTERNS: ClassVar[list[str]] = [
        # Python stdlib et packages courants
        r'^os\.path\.',          r'^sys\.path\.',       r'^site-packages\.',
        r'^distutils\.',         r'^setuptools\.',       r'^pip\.',
        r'^importlib\.',         r'^collections\.',      r'^itertools\.',
        r'^functools\.',         r'^pathlib\.',          r'^urllib\.',
        r'^http\.client\.',      r'^http\.server\.',     r'^email\.',
        r'^xml\.etree\.',        r'^xmlrpc\.',           r'^json\.',
        r'^logging\.',           r'^unittest\.',         r'^asyncio\.',
        r'^concurrent\.',        r'^multiprocessing\.',  r'^threading\.',
        r'^socket\.',            r'^ssl\.',              r'^hashlib\.',
        r'^hmac\.',              r'^base64\.',           r'^binascii\.',
        r'^struct\.',            r'^io\.',               r'^typing\.',
        r'^abc\.',               r'^dataclasses\.',      r'^enum\.',
        r'^copy\.',              r'^re\.',               r'^string\.',
        r'^textwrap\.',          r'^pprint\.',           r'^inspect\.',
        r'^traceback\.',         r'^warnings\.',         r'^contextlib\.',
        r'^weakref\.',           r'^gc\.',               r'^platform\.',
        r'^subprocess\.',        r'^shutil\.',           r'^tempfile\.',
        r'^fnmatch\.',           r'^glob\.',             r'^stat\.',
        r'^time\.',              r'^datetime\.',         r'^calendar\.',
        r'^math\.',              r'^random\.',           r'^statistics\.',
        r'^decimal\.',           r'^fractions\.',        r'^numbers\.',
        r'^array\.',             r'^queue\.',            r'^heapq\.',
        r'^bisect\.',            r'^pickle\.',           r'^shelve\.',
        r'^sqlite3\.',           r'^csv\.',              r'^configparser\.',
        r'^argparse\.',          r'^getopt\.',           r'^optparse\.',
        r'^getpass\.',           r'^readline\.',         r'^rlcompleter\.',
        r'^code\.',              r'^codeop\.',           r'^pdb\.',
        r'^profile\.',           r'^timeit\.',           r'^trace\.',
        r'^linecache\.',         r'^tokenize\.',         r'^token\.',
        r'^ast\.',               r'^dis\.',              r'^py_compile\.',
        r'^compileall\.',        r'^zipimport\.',        r'^zipfile\.',
        r'^tarfile\.',           r'^gzip\.',             r'^bz2\.',
        r'^lzma\.',              r'^zlib\.',
        # Java packages
        r'^java\.',              r'^javax\.',            r'^org\.apache\.',
        r'^org\.springframework\.', r'^com\.google\.',  r'^org\.junit\.',
        r'^com\.fasterxml\.',    r'^io\.netty\.',        r'^org\.slf4j\.',
        r'^ch\.qos\.',           r'^org\.hibernate\.',
        # .NET / C# namespaces
        r'^System\.',            r'^Microsoft\.',        r'^Windows\.',
        r'^mscorlib\.',          r'^netstandard\.',
        # C runtime et bibliothèques système
        r'^msvcr\d+\.',          r'^msvcp\d+\.',         r'^vcruntime\.',
        r'^ucrtbase\.',          r'^api-ms-win-',        r'^ext-ms-win-',
        # Compilateurs et outils
        r'^GCC:',                r'^LLVM ',              r'^clang ',
        r'^__GNUC__',            r'^_POSIX_',
    ]

    # Sections PE/ELF courantes
    BINARY_SECTION_PATTERNS: ClassVar[list[str]] = [
        # Sections PE standard
        r'^\.(text|data|rdata|bss|idata|edata|pdata|reloc|rsrc|tls)$',
        r'^\.(debug|didat|sxdata|gfids|gehcont|00cfg)$',
        r'^(CODE|DATA|BSS|.icode|.ocode)$',
        # Sections de runtime .NET
        r'^\.(sdata|sdatab|srdata)$',
        r'^(\.CLR_UEF|\.managed)$',
        # Sections MinGW / GCC
        r'^\.(CRT\$|ctors|dtors|eh_fram|gcc_exc).*',
        r'^(\.rdata\$|\.data\$|\.text\$).*',
        # Sections Delphi
        r'^(CODE|DATA|BSS|\.itext|\.didata)$',
    ]

    # Extensions à exclure des domaines
    FILE_EXTENSIONS: ClassVar[set[str]] = {
        # Images
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "tiff",
        # Fonts
        "woff", "woff2", "ttf", "otf", "eot",
        # Documents
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        # Archives
        "zip", "tar", "gz", "rar", "7z", "bz2",
        # Médias
        "mp3", "mp4", "avi", "mov", "mkv", "flv", "wav",
        # Web
        "css", "js", "html", "htm", "xml", "json", "wasm",
        # Code / config
        "py", "java", "cs", "cpp", "c", "h", "rs", "go", "yaml", "toml",
        # Binaires
        "exe", "dll", "so", "dylib", "bin", "dat",
    }

    _compiled_system_modules: ClassVar[re.Pattern[str] | None] = None
    _compiled_binary_sections: ClassVar[re.Pattern[str] | None] = None

    @classmethod
    def _get_compiled_system_modules(cls) -> re.Pattern[str]:
        if cls._compiled_system_modules is None:
            combined = "|".join(f"(?:{p})" for p in cls.SYSTEM_MODULE_PATTERNS)
            cls._compiled_system_modules = re.compile(combined, re.IGNORECASE)
        return cls._compiled_system_modules

    @classmethod
    def _get_compiled_binary_sections(cls) -> re.Pattern[str]:
        if cls._compiled_binary_sections is None:
            combined = "|".join(f"(?:{p})" for p in cls.BINARY_SECTION_PATTERNS)
            cls._compiled_binary_sections = re.compile(combined, re.IGNORECASE)
        return cls._compiled_binary_sections

    @staticmethod
    def is_valid_tld(tld: str) -> bool:
        """Vérifie si un TLD est valide."""
        return tld.lower() in WhitelistFilter.VALID_TLDS

    @staticmethod
    def is_benign_domain_static(domain: str) -> bool:
        """Vérifie si un domaine fait partie de la whitelist des domaines bénins."""
        domain = domain.lower()
        if domain in WhitelistFilter.BENIGN_DOMAINS:
            return True
        # Vérification des sous-domaines (ex: foo.microsoft.com)
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            sub = ".".join(parts[i:])
            if sub in WhitelistFilter.BENIGN_DOMAINS:
                return True
        return False

    @staticmethod
    def is_system_module_static(value: str) -> bool:
        """Vérifie si une chaîne correspond à un pattern de module système."""
        pattern = WhitelistFilter._get_compiled_system_modules()
        return bool(pattern.match(value))

    @staticmethod
    def is_binary_section_static(value: str) -> bool:
        """Vérifie si une chaîne correspond à un pattern de section binaire."""
        pattern = WhitelistFilter._get_compiled_binary_sections()
        return bool(pattern.match(value))

    @staticmethod
    def is_file_extension(value: str) -> bool:
        """Vérifie si la valeur (qui a matché un domaine) est en fait une extension."""
        # Un TLD matché peut être un faux positif d'une extension de fichier
        tld = value.rsplit(".", 1)[-1].lower() if "." in value else value.lower()
        return tld in WhitelistFilter.FILE_EXTENSIONS

    @staticmethod
    def is_rfc1918(ip: str) -> bool:
        """Vérifie si une IP (IPv4 ou IPv6) fait partie des réseaux privés/locaux."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local
        except ValueError:
            return False
