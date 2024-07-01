CREATE TABLE IF NOT EXISTS alienvault_results (domain TEXT, subdomain TEXT);
CREATE TABLE IF NOT EXISTS anubis_results (domain TEXT, subdomain TEXT);
CREATE TABLE IF NOT EXISTS asnmap_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS assetfinder_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS censys_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS cert_spotter_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS crtsh_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS gospider_results (subdomain TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS hackertarget_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS httpx_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS katana_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS naabu_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS rapiddns_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS security_trails_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS shodan_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS spyse_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS subfinder_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS tlsx_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS urlscan_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS virus_total_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS wapiti_results (target TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS directory_wordlists (filename TEXT, content TEXT);
CREATE TABLE IF NOT EXISTS brute_wordlists (filename TEXT, content TEXT);
CREATE TABLE IF NOT EXISTS fuzz_wordlists (filename TEXT, content TEXT);
CREATE TABLE IF NOT EXISTS nuclei_templates (filename TEXT, content TEXT);