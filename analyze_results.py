#!/usr/bin/env python3
import sqlite3
import sys
from typing import List, Dict, Set
from tabulate import tabulate
import json
from datetime import datetime
import logging
import os

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('analyzer')

DATABASE = 'results.db'

class ResultAnalyzer:
    def __init__(self, database: str = DATABASE):
        self.database = database
        self.passive_tools = [
            'alienvault',
            'anubis',
            'censys',
            'cert_spotter',
            'crtsh',
            'hackertarget',
            'rapiddns',
            'security_trails',
            'shodan',
            'urlscan',
            'virus_total'
        ]
        
        self.active_tools = [
            'asnmap',
            'assetfinder',
            'gospider',
            'httpx',
            'katana',
            'naabu',
            'subfinder',
            'tlsx',
            'wapiti',
            'whatweb',
            'wafw00f',
            'waybackurls',
            'hakrawler',
            'cmseek'
        ]

    def connect_db(self) -> sqlite3.Connection:
        """Create a database connection."""
        if not os.path.exists(self.database):
            logger.error(f"Database file {self.database} not found!")
            sys.exit(1)
            
        try:
            conn = sqlite3.connect(self.database)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            logger.error(f"Error connecting to database: {e}")
            raise

    def get_all_domains(self) -> List[str]:
        """Get all unique domains from the database."""
        try:
            with self.connect_db() as conn:
                c = conn.cursor()
                domains = set()
                
                # First check tool_executions table
                try:
                    results = c.execute("SELECT DISTINCT target FROM tool_executions").fetchall()
                    domains.update(row['target'] for row in results)
                except sqlite3.OperationalError as e:
                    logger.debug(f"Error querying tool_executions: {e}")
                
                # Then check all tool tables
                for tool in self.passive_tools + self.active_tools:
                    table = f"{tool}_results"
                    try:
                        results = c.execute(f"SELECT DISTINCT domain FROM {table}").fetchall()
                        domains.update(row['domain'] for row in results)
                    except sqlite3.OperationalError as e:
                        logger.debug(f"Error querying {table}: {e}")
                        continue
                        
                return sorted(list(domains))
        except Exception as e:
            logger.error(f"Error getting domains: {e}")
            return []

    def get_tool_results(self, domain: str, tool: str) -> List[Dict]:
        """Get detailed results for a specific tool and domain."""
        try:
            with self.connect_db() as conn:
                c = conn.cursor()
                table = f"{tool}_results"
                try:
                    # Get all columns for the tool's results
                    c.execute(f"SELECT * FROM {table} WHERE domain = ?", (domain,))
                    columns = [description[0] for description in c.description]
                    results = c.execute(f"SELECT * FROM {table} WHERE domain = ?", (domain,)).fetchall()
                    return [dict(zip(columns, row)) for row in results]
                except sqlite3.OperationalError as e:
                    logger.debug(f"Error querying {table}: {e}")
                    return []
        except Exception as e:
            logger.error(f"Error getting results for {tool}: {e}")
            return []

    def get_execution_history(self, domain: str = None, tool: str = None) -> List[Dict]:
        """Get tool execution history with optional filtering."""
        with self.connect_db() as conn:
            c = conn.cursor()
            query = """SELECT tool, target, start_time, end_time, status, error, subdomains_found 
                      FROM tool_executions"""
            conditions = []
            params = []
            
            if domain:
                conditions.append("target = ?")
                params.append(domain)
            if tool:
                conditions.append("tool = ?")
                params.append(tool)
                
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
                
            query += " ORDER BY start_time DESC"
            
            try:
                results = c.execute(query, params).fetchall()
                return [dict(row) for row in results]
            except sqlite3.OperationalError as e:
                logger.error(f"Error querying execution history: {e}")
                return []

    def analyze_domain(self, domain: str, include_details: bool = False) -> Dict:
        """Analyze results for a specific domain."""
        logger.info(f"Analyzing domain: {domain}")
        results = {
            'domain': domain,
            'total_unique_subdomains': 0,
            'tools': {},
            'subdomains': set(),
            'execution_history': self.get_execution_history(domain)
        }
        
        # Analyze passive tools
        for tool in self.passive_tools:
            logger.debug(f"Processing {tool}...")
            tool_results = self.get_tool_results(domain, tool)
            
            if include_details:
                results['tools'][tool] = {
                    'count': len(tool_results),
                    'results': tool_results
                }
            else:
                subdomains = [r['subdomain'] for r in tool_results if 'subdomain' in r]
                results['tools'][tool] = {
                    'count': len(subdomains),
                    'subdomains': subdomains
                }
            
            results['subdomains'].update(r['subdomain'] for r in tool_results if 'subdomain' in r)
            
        # Analyze active tools
        for tool in self.active_tools:
            logger.debug(f"Processing {tool}...")
            tool_results = self.get_tool_results(domain, tool)
            
            if include_details:
                results['tools'][tool] = {
                    'count': len(tool_results),
                    'results': tool_results
                }
            else:
                subdomains = [r['subdomain'] for r in tool_results if 'subdomain' in r]
                results['tools'][tool] = {
                    'count': len(subdomains),
                    'subdomains': subdomains
                }
            
            results['subdomains'].update(r['subdomain'] for r in tool_results if 'subdomain' in r)
        
        results['total_unique_subdomains'] = len(results['subdomains'])
        results['subdomains'] = sorted(list(results['subdomains']))
        
        logger.info(f"Found {results['total_unique_subdomains']} unique subdomains")
        return results

    def print_summary(self, analysis: Dict):
        """Print a formatted summary of the analysis."""
        print(f"\n=== Analysis for {analysis['domain']} ===")
        print(f"Total Unique Subdomains Found: {analysis['total_unique_subdomains']}")
        
        # Print execution history
        if analysis['execution_history']:
            print("\nExecution History:")
            history_table = []
            for entry in analysis['execution_history']:
                history_table.append([
                    entry['tool'],
                    entry['status'],
                    entry['subdomains_found'],
                    entry['start_time'],
                    entry['end_time'],
                    entry['error'] if entry['error'] else 'None'
                ])
            
            print(tabulate(
                history_table,
                headers=['Tool', 'Status', 'Subdomains', 'Start Time', 'End Time', 'Error'],
                tablefmt='grid'
            ))
        
        # Print tool results
        tool_rows = []
        for tool, data in analysis['tools'].items():
            if data['count'] > 0:  # Only show tools that found something
                tool_rows.append([tool, data['count']])
        
        if tool_rows:
            print("\nResults by Tool:")
            print(tabulate(
                sorted(tool_rows, key=lambda x: x[1], reverse=True),
                headers=['Tool', 'Subdomains Found'],
                tablefmt='grid'
            ))
        
        if analysis['subdomains']:
            print("\nAll Unique Subdomains:")
            for subdomain in analysis['subdomains']:
                print(f"- {subdomain}")

    def export_json(self, analysis: Dict, output_file: str):
        """Export analysis results to a JSON file."""
        try:
            with open(output_file, 'w') as f:
                json.dump(analysis, f, indent=2)
            logger.info(f"Results exported to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting results: {e}")

def print_usage():
    print("""
Usage: python3 analyze_results.py [OPTIONS]

Options:
  -d, --domain DOMAIN    Target domain to analyze
  -l, --list-domains    List all domains in the database
  -H, --history         Show execution history
  -e, --export FILE     Export results to JSON file
  -a, --all            Analyze all domains in the database
  -D, --details        Include detailed tool results in analysis
  --debug              Enable debug logging
  -t, --tool TOOL      Filter history by tool name
  -h, --help           Show this help message
""")

def parse_args(args):
    options = {
        'domain': None,
        'list_domains': False,
        'history': False,
        'export': None,
        'all': False,
        'details': False,
        'debug': False,
        'tool': None
    }
    
    i = 1
    while i < len(args):
        arg = args[i]
        if arg in ['-h', '--help']:
            print_usage()
            sys.exit(0)
        elif arg in ['-d', '--domain']:
            i += 1
            if i < len(args):
                options['domain'] = args[i]
        elif arg in ['-l', '--list-domains']:
            options['list_domains'] = True
        elif arg in ['-H', '--history']:
            options['history'] = True
        elif arg in ['-e', '--export']:
            i += 1
            if i < len(args):
                options['export'] = args[i]
        elif arg in ['-a', '--all']:
            options['all'] = True
        elif arg in ['-D', '--details']:
            options['details'] = True
        elif arg == '--debug':
            options['debug'] = True
        elif arg in ['-t', '--tool']:
            i += 1
            if i < len(args):
                options['tool'] = args[i]
        i += 1
    
    return options

def main():
    if len(sys.argv) == 1:
        print_usage()
        return
    
    args = parse_args(sys.argv)
    
    if args['debug']:
        logger.setLevel(logging.DEBUG)
    
    try:
        analyzer = ResultAnalyzer()
        
        if args['list_domains']:
            domains = analyzer.get_all_domains()
            if domains:
                print("\nDomains in database:")
                for domain in domains:
                    print(f"- {domain}")
            else:
                print("\nNo domains found in the database.")
            return
            
        if args['history']:
            history = analyzer.get_execution_history(args['domain'], args['tool'])
            if not history:
                print("No execution history found.")
                return
            
            print("\nExecution History:")
            history_table = []
            for entry in history:
                history_table.append([
                    entry['tool'],
                    entry['target'],
                    entry['start_time'],
                    entry['end_time'],
                    entry['status'],
                    entry['subdomains_found'],
                    entry['error'] if entry['error'] else 'None'
                ])
            
            print(tabulate(
                history_table,
                headers=['Tool', 'Target', 'Start Time', 'End Time', 'Status', 'Subdomains', 'Error'],
                tablefmt='grid'
            ))
            return
        
        if args['all']:
            domains = analyzer.get_all_domains()
        elif args['domain']:
            domains = [args['domain']]
        else:
            print_usage()
            return
        
        for domain in domains:
            try:
                analysis = analyzer.analyze_domain(domain, include_details=args['details'])
                if args['export']:
                    output_file = args['export'] if len(domains) == 1 else f"{domain}_{args['export']}"
                    analyzer.export_json(analysis, output_file)
                else:
                    analyzer.print_summary(analysis)
            except Exception as e:
                logger.error(f"Error analyzing domain {domain}: {e}")
                continue
                
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 