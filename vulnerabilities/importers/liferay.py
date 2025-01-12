import urllib.parse as urlparse
import re

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import GenericVersionRange
from univers.versions import GenericVersion

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity


class LiferayImporter(Importer):
    root_url = "https://liferay.dev/portal/security/known-vulnerabilities"
    license_url = "https://github.com/liferay/liferay-portal/blob/master/LICENSE.md"
    spdx_license_expression = "LGPL-2.1-or-later"
    importer_name = "Liferay Importer"

    def advisory_data(self):
        known_urls = {self.root_url}
        visited_urls = set()
        data_by_url = {}

        while True:
            unvisited_urls = known_urls - visited_urls
            for url in unvisited_urls:
                data = requests.get(url).content
                data_by_url[url] = data
                visited_urls.add(url)
                known_urls.update(find_advisory_urls(data))

            if known_urls == visited_urls:
                break

        for url, data in data_by_url.items():
            yield from to_advisories(data)


def find_advisory_urls(page_data):
    """Find all CVE advisory URLs from a page."""
    soup = BeautifulSoup(page_data, features="lxml")
    urls = set()
    
    list_items = soup.select("li.list-group-item")
    for item in list_items:
        link = item.select_one("a")
        if link and "CVE-" in link.text:
            cve_match = re.search(r'(CVE-\d{4}-\d+)', link.text)
            if cve_match:
                cve_id = cve_match.group(1).lower()
                url = f"https://liferay.dev/portal/security/known-vulnerabilities/-/asset_publisher/jekt/content/{cve_id}"
                urls.add(url)
    
    return urls


def clean_version(version):
    """Clean version string by replacing + with . and removing any ga tags"""
    if not version:
        return version
    return version.replace('+', '.').replace('-ga', '')


def get_section_content(article, section_name):
    """Extract content from a specific section in the advisory."""
    section = article.find("h3", text=re.compile(section_name, re.I))
    if not section:
        return ""
        
    content_elements = []
    current = section.find_next_sibling()
    
    while current and current.name != "h3":
        if current.name == "p":
            text = current.get_text(strip=True)
            if text:
                content_elements.append(text)
        elif current.name == "ul":
            items = [li.get_text(strip=True) for li in current.find_all("li")]
            content_elements.extend(items)
        current = current.find_next_sibling()
    
    if len(content_elements) > 1:
        return "\n".join(content_elements)
    elif len(content_elements) == 1:
        return content_elements[0]
    return ""


def extract_version(version_text):
    """Extract version number from version text."""
    patterns = [
        r'(\d+\.\d+\.\d+\.\d+)(?:-ga\d+)?',  # Matches 7.4.3.39-ga39
        r'(\d+\.\d+\.\d+)',                   # Matches 7.4.3
        r'(\d+\.\d+)',                        # Matches 7.4
    ]
    
    for pattern in patterns:
        match = re.search(pattern, version_text)
        if match:
            return match.group(1)
    return None


def extract_update_number(version_text):
    """Extract update number from DXP version text."""
    patterns = [
        r'update (\d+)',            # Matches "update 38"
        r'through update (\d+)',    # Matches "through update 38"
    ]
    
    for pattern in patterns:
        match = re.search(pattern, version_text.lower())
        if match:
            return match.group(1)
    return None


def get_dxp_update_range(base_version):
    """Get the update range for a DXP version."""
    try:
        major, minor = base_version.split('.')[:2]
        return (f"{major}.{minor}.0", f"{major}.{minor}.100")
    except ValueError:
        return None


def parse_affected_versions(article):
    """Parse affected version ranges for both Portal and DXP."""
    affected_versions = {"portal": [], "dxp": []}
    affected_section = article.find("h3", text=re.compile("Affected Version", re.I))
    
    if affected_section:
        current = affected_section.find_next_sibling()
        while current and current.name != "h3":
            if current.name == "ul":
                for item in current.find_all("li"):
                    version_text = item.get_text(strip=True)
                    if "Portal" in version_text:
                        if "through" in version_text:
                            parts = version_text.split("through")
                            start_ver = clean_version(extract_version(parts[0]))
                            end_ver = clean_version(extract_version(parts[1]))
                            if start_ver and end_ver:
                                affected_versions["portal"].append((start_ver, end_ver))
                    elif "DXP" in version_text:
                        if "through update" in version_text.lower():
                            base_ver = clean_version(extract_version(version_text))
                            update_num = extract_update_number(version_text)
                            if base_ver and update_num:
                                affected_versions["dxp"].append((f"{base_ver}.0", f"{base_ver}.{update_num}"))
                        else:
                            # Single DXP version - get the update range
                            base_ver = clean_version(extract_version(version_text))
                            if base_ver:
                                update_range = get_dxp_update_range(base_ver)
                                if update_range:
                                    affected_versions["dxp"].append(update_range)
            current = current.find_next_sibling()
            
    return affected_versions


def parse_fixed_versions(article):
    """Parse fixed versions for both Portal and DXP."""
    fixed_versions = {"portal": [], "dxp": []}
    fixed_section = article.find("h3", text=re.compile("Fixed Version", re.I))
    
    if fixed_section:
        current = fixed_section.find_next_sibling()
        while current and current.name != "h3":
            if current.name == "ul":
                for item in current.find_all("li"):
                    version_text = item.get_text(strip=True)
                    if "Portal" in version_text:
                        version = None
                        link = item.find("a")
                        if link:
                            version = clean_version(extract_version(link.get_text(strip=True)))
                        if not version:
                            version = clean_version(extract_version(version_text))
                        if version:
                            fixed_versions["portal"].append(version)
                    elif "DXP" in version_text:
                        base_ver = clean_version(extract_version(version_text))
                        update_num = extract_update_number(version_text)
                        if base_ver and update_num:
                            fixed_versions["dxp"].append(f"{base_ver}.{update_num}")
                        elif base_ver:
                            fixed_versions["dxp"].append(f"{base_ver}.0")
            current = current.find_next_sibling()
            
    return fixed_versions


def create_affected_packages(product, affected_versions, fixed_versions):
    """Create AffectedPackage objects for a product."""
    packages = []
    
    for start_ver, end_ver in affected_versions:
        if start_ver and end_ver:  # Ensure both versions exist
            try:
                version_range = GenericVersionRange.from_versions([start_ver, end_ver])
                # Create one package per fixed version
                for fixed_version in fixed_versions:
                    if fixed_version:
                        fixed_ver = clean_version(fixed_version)
                        packages.append(
                            AffectedPackage(
                                package=PackageURL(
                                    type="generic",
                                    name=f"liferay-{product}",
                                ),
                                affected_version_range=version_range,
                                fixed_version=GenericVersion(fixed_ver)
                            )
                        )
            except Exception as e:
                print(f"Error creating version range for {start_ver} to {end_ver}: {e}")
    
    return packages


def to_advisories(data):
    """Convert page data into advisory objects."""
    advisories = []
    soup = BeautifulSoup(data, features="lxml")
    article = soup.find("article")
    
    if not article:
        return advisories

    cve_id = None
    title_span = soup.find("span", class_="asset-title d-inline")
    if title_span:
        cve_match = re.search(r'(CVE-\d{4}-\d+)', title_span.text)
        if cve_match:
            cve_id = cve_match.group(1)

    if not cve_id:
        return advisories

    description = get_section_content(article, "Description")
    severity = None
    severity_text = get_section_content(article, "Severity")
    if severity_text:
        severity_match = re.search(r'(\d+\.?\d*)\s*\((CVSS:[^)]+)\)', severity_text)
        if severity_match:
            score, vector = severity_match.groups()
            severity = VulnerabilitySeverity(
                system=severity_systems.CVSSV4 if "CVSS:4.0" in vector else severity_systems.CVSSV3,
                value=score,
                scoring_elements=vector
            )

    affected_versions = parse_affected_versions(article)
    fixed_versions = parse_fixed_versions(article)

    affected_packages = []
    for product in ["portal", "dxp"]:
        if affected_versions.get(product):
            affected_packages.extend(
                create_affected_packages(
                    product,
                    affected_versions[product],
                    fixed_versions.get(product, [])
                )
            )

    url = f"https://liferay.dev/portal/security/known-vulnerabilities/-/asset_publisher/jekt/content/{cve_id.lower()}"
    references = [Reference(url=url, severities=[severity] if severity else [])]

    advisories.append(
        AdvisoryData(
            aliases=[cve_id],
            summary=description,
            references=references,
            affected_packages=affected_packages,
            url=url
        )
    )

    return advisories