import httpx
from functools import lru_cache
from core.logger import get_logger

logger = get_logger(__name__)

MAVEN_TO_EUVD: dict[tuple, tuple] = {
    ("apache", "log4j-core"):              ("apache", "log4j2"),
    ("apache", "log4j-api"):               ("apache", "log4j2"),
    ("apache", "log4j-slf4j2-impl"):       ("apache", "log4j2"),
    ("org.apache.logging.log4j", "log4j-core"): ("apache", "log4j2"),
    ("org.apache.logging.log4j", "log4j-api"):  ("apache", "log4j2"),
    ("apache", "struts2-core"):            ("apache", "struts"),
    ("org.apache.struts", "struts2-core"): ("apache", "struts"),
    ("org.springframework", "spring-webmvc"):  ("vmware", "spring framework"),
    ("org.springframework", "spring-core"):    ("vmware", "spring framework"),
    ("org.springframework", "spring-beans"):   ("vmware", "spring framework"),
    ("org.springframework", "spring-context"): ("vmware", "spring framework"),
    ("spring-cloud-function-context", "spring-cloud-function-context"): ("vmware", "spring cloud function"),
    ("spring-cloud-gateway-server",   "spring-cloud-gateway-server"):   ("vmware", "spring cloud gateway"),
    ("com.fasterxml.jackson.core", "jackson-databind"):              ("fasterxml", "jackson-databind"),
    ("com.fasterxml.jackson.core", "jackson-annotations"):           ("fasterxml", "jackson-databind"),
    ("com.fasterxml.jackson.dataformat", "jackson-dataformat-yaml"): ("fasterxml", "jackson-databind"),
    ("commons-collections", "commons-collections"): ("apache", "commons collections"),
    ("apache", "commons-collections4"):    ("apache", "commons collections"),
    ("apache", "commons-text"):            ("apache", "commons text"),
    ("apache", "commons-lang3"):           ("apache", "commons lang"),
    ("commons-io", "commons-io"):          ("apache", "commons io"),
    ("org.apache.commons", "commons-text"):         ("apache", "commons text"),
    ("org.apache.commons", "commons-collections4"): ("apache", "commons collections"),
    ("netty-all",    "netty-all"):    ("netty", "netty"),
    ("netty-buffer", "netty-buffer"): ("netty", "netty"),
    ("io.netty",     "netty-all"):    ("netty", "netty"),
    ("io.netty",     "netty-buffer"): ("netty", "netty"),
    ("hibernate-core",  "hibernate-core"): ("red hat", "hibernate orm"),
    ("org.hibernate",   "hibernate-core"): ("red hat", "hibernate orm"),
    ("com.h2database", "h2"):              ("h2database", "h2"),
    ("snakeyaml",  "snakeyaml"):           ("snakeyaml project", "snakeyaml"),
    ("org.yaml",   "snakeyaml"):           ("snakeyaml project", "snakeyaml"),
    ("com.thoughtworks.xstream", "xstream"): ("xstream project", "xstream"),
    ("apache",           "shiro-core"):    ("apache", "shiro"),
    ("org.apache.shiro", "shiro-core"):    ("apache", "shiro"),
    ("com.alibaba", "fastjson"):           ("alibaba", "fastjson"),
    ("com.google.guava", "guava"):         ("google", "guava"),
    ("org.bouncycastle", "bcprov-jdk15on"): ("legion of the bouncy castle", "bouncy castle"),
    ("org.bouncycastle", "bcprov-jdk18on"): ("legion of the bouncy castle", "bouncy castle"),
    ("org.eclipse.jetty", "jetty-server"): ("eclipse", "jetty"),
    ("apache",                  "tomcat-embed-core"): ("apache", "tomcat"),
    ("org.apache.tomcat.embed", "tomcat-embed-core"): ("apache", "tomcat"),
    ("com.fasterxml.woodstox", "woodstox-core"): ("fasterxml", "woodstox"),
}

def parse_cpe(cpe: str) -> dict:
    parts = cpe.split(":")
    return {
        "vendor":  parts[3] if len(parts) > 3 else "*",
        "product": parts[4] if len(parts) > 4 else "*",
        "version": parts[5] if len(parts) > 5 else "*",
    }


def resolve_euvd_names(cpe: str) -> list[tuple[str, str]]:
    parsed  = parse_cpe(cpe)
    vendor  = parsed["vendor"]
    product = parsed["product"]

    candidates = []
    key = (vendor, product)
    if key in MAVEN_TO_EUVD:
        candidates.append(MAVEN_TO_EUVD[key])

    short_vendor = vendor.split(".")[-1] if "." in vendor else vendor
    short_key    = (short_vendor, product)
    if short_key in MAVEN_TO_EUVD and short_key != key:
        candidates.append(MAVEN_TO_EUVD[short_key])

    raw_vendor  = short_vendor.replace("-", " ")
    raw_product = product.replace("-", " ").replace("_", " ")
    raw = (raw_vendor, raw_product)
    if raw not in candidates:
        candidates.append(raw)

    short_product = product.split("-")[0]
    if len(short_product) > 4 and short_product != product:
        short = (raw_vendor, short_product)
        if short not in candidates:
            candidates.append(short)

    seen, result = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result


@lru_cache(maxsize=1024)
def resolve_maven_group_id(artifact_id: str) -> str | None:
    url = f"https://search.maven.org/solrsearch/select?q=a:{artifact_id}&rows=1&wt=json"
    
    try:
        with httpx.Client() as client:
            response = client.get(url, timeout=5.0)
            response.raise_for_status()
            data = response.json()
            docs = data.get("response", {}).get("docs", [])
            
            if docs:
                found_group_id = docs[0].get("g")
                logger.debug(f"[CPE Mapper] Resolved {artifact_id} -> {found_group_id}")
                return found_group_id
    except Exception as e:
        logger.warning(f"[CPE Mapper] Failed to resolve Maven Group ID for {artifact_id}: {e}")
        
    return None

def cpe_to_osv_package(cpe: str) -> dict | None:
    parsed  = parse_cpe(cpe)
    vendor  = parsed["vendor"]
    product = parsed["product"]

    if "." in vendor:
        return {"name": f"{vendor}:{product}", "ecosystem": "Maven"}

    dynamic_group_id = resolve_maven_group_id(product)
    if dynamic_group_id:
        return {"name": f"{dynamic_group_id}:{product}", "ecosystem": "Maven"}

    return None