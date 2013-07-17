#!/usr/bin/env python
'''
Author: moloch
License: GPLv2
About: Convert Fortify xml documents to useful formats
'''
import os
import sys
import platform
import argparse
import xml.dom.minidom

### Setup Stuff
if platform.system().lower() in ['linux', 'darwin']:
    INFO = "\033[1m\033[36m[*]\033[0m "
    WARN = "\033[1m\033[31m[!]\033[0m "
else:
    INFO = "[*] "
    WARN = "[!] "

def print_info(msg):
    sys.stdout.write(chr(27) + '[2K')
    sys.stdout.write('\r' + INFO + msg)
    sys.stdout.flush()

try:
    from xlsxwriter.workbook import Workbook
except ImportError:
    print(WARN+'''Warning: xlsxwriter library is not installed, cannot output xlsx format.
Download it from: https://pypi.python.org/pypi/XlsxWriter ''')

try:
    import xml.etree.cElementTree as ET
except ImportError:
    print(WARN+'Warning: Failed to import cElementTree, falling back to ElementTree')
    import xml.etree.ElementTree as ET

### Classes
class Finding(object):
    ''' 
    Holds data for a single Fortify finding, sortable by severity (rank)
    '''

    def __init__(self, category, severity, file_name, file_path, line_start, target_function=None):
        self.category = category      # <Category />
        self.severity = severity      # <Folder />
        self.file_name = file_name    # <FileName />
        self.file_path = file_path    # <FilePath />
        self.line_start = line_start  # <LineStart />
        self.target_function = str(target_function)
        self._ranks = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
        }

    @property
    def rank(self):
        ''' Integer based on severity, used for sorting '''
        return _ranks[self.severity.lower()]

    def __cmp__(self, other):
        ''' Allows us to call bult-in sort() '''
        if self.rank < other.rank:
            return 1
        elif self.rank == other.rank:
            return 0
        else:
            return -1


class FortifyReport(object):
    ''' Python object based on the Fortify report xml data '''

    def __init__(self, file_path):
        self.fname = file_path
        self.tree = ET.parse(self.fname)
        self.doc = self.tree.getroot()
        self._findings = None
        self._severity_formats = None

    def fix(self, output):
        ''' Fix DOM structure and output '''
        fout = sys.stdout if output is None else open(output, 'w')
        xml_dom = xml.dom.minidom.parse(self.fname)
        fout.write(xml_dom.toprettyxml())

    @property
    def findings(self):
        ''' Parse DOM and return list of Finding objects '''
        if self._findings is None:
            self._findings = {'critical': [], 'high': [], 'medium': [], 'low': []}
            for section in self.report_sections:
                groupings = self.get_groupings(section)
                for index, group in enumerate(groupings):
                    stats = (index + 1, len(groupings), group.get('count'),)
                    print_info("Parsing group %02d of %02d, with %s finding(s)" % stats)
                    group_title = self.get_children_by_tag(group, 'grouptitle')[0]
                    self._generate_findings(group)
                print_info("Finished parsing %d grouping(s)\n" % len(groupings))
        return self._findings

    def get_groupings(self, section):
        ''' Traverse DOM and return groups '''
        try:
            kids = self.get_children_by_tag(section, 'subsection')[0]
            kids = self.get_children_by_tag(kids, 'issuelisting')[0]
            kids = self.get_children_by_tag(kids, 'chart')[0]
            groups = self.get_children_by_tag(kids, 'groupingsection')
            print_info("Found %d grouping(s) in %s\n" % (len(groups), self.fname))
            return groups
        except IndexError:
            print(WARN+"Error: Failed to parse report body, missing required tag.")
            os._exit(1)

    def _generate_findings(self, group):
        ''' Creates a list of findings based on a grouping '''
        pass

    @property
    def report_sections(self):
        ''' Return only report sections that contain subsections '''
        kids = self.get_children_by_tag(self.doc, 'reportsection')
        _sections = filter(lambda child: child.get('optionalSubsections').lower() == 'true', kids)
        print_info("Found %d report section(s)\n" % len(_sections))
        return _sections

    def get_children_by_tag(self, elem, tag_name):
        ''' Return child elements with a given tag '''
        return filter(
            lambda child: child.tag.lower() == tag_name, elem.getchildren()
        )

    def to_csv(self, output):
        ''' Create a csv file based on findings '''
        for category in self.findings:
            pass

    def to_xlsx(self, output):
        ''' Create a Excel spreadsheet based on the findings '''
        fout = output if output is not None else 'FortifyReport.xlsx'
        if not fout.endswith('.xlsx'): fout += ".xlsx"
        workbook = Workbook(fout)
        for risk_level in self.findings:
            if 0 < len(self.findings[risk_level]):
                print_info("Writting %s risk details to spreadsheet\n" % risk_level)
                worksheet = workbook.add_worksheet(risk_level.title())
                self._add_column_names(workbook, worksheet)
                for index, vuln in enumerate(self.findings[risk_level]):
                    worksheet.write("A%d" % index + 2, vuln.category)
                    worksheet.write("B%d" % index + 2, vuln.file_name)
                    worksheet.write("C%d" % index + 2, vuln.line_start)
                    worksheet.write("D%d" % index + 2, vuln.target_function)
                    worksheet.write("E%d" % index + 2, vuln.file_path)
        print_info("Saved output to: %s\n" % fout)
        workbook.close()

    def _add_column_names(self, workbook, worksheet):
        cell_format = workbook.add_format()
        cell_format.set_bold()
        cell_format.set_font_color('white')
        cell_format.set_bg_color('blue')
        worksheet.write("A1", "Category", cell_format)
        worksheet.write("B1", "File Name", cell_format)
        worksheet.write("C1", "Line Start", cell_format)
        worksheet.write("D1", "Target Function", cell_format)
        worksheet.write("E1", "File Path", cell_format)

### Main Function
def main(args):
    ''' Call functions based on user args '''
    report = FortifyReport(args.target)
    formats = {
        'xml': report.fix,
        'xlsx': report.to_xlsx,
        'csv': report.to_csv,
    }
    if args.format not in formats:
        print(WARN+'Error: Output format not supported.')
    else:
        if args.output is not None and os.path.exists(args.output):
            print(WARN+"Warning: Overwriting file %s" % args.output)
        formats[args.format](args.output)


### CLI Code
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Convert Fortify reports to a friendly spreadsheet formats',
    )
    parser.add_argument('--version',
        action='version',
        version='%(prog)s v0.1'
    )
    parser.add_argument('--target', '-t',
        help='target Fortify report .xml file',
        dest='target',
        required=True,
    )
    parser.add_argument('--output', '-o',
        help='ouput file (default: stdout)',
        dest='output',
        default=None,
    )
    parser.add_argument('--format', '-f',
        help='ouptut format can be: xml, xlsx, or csv (default: xlsx)',
        dest='format',
        default='xlsx',
    )
    args = parser.parse_args()
    if os.path.exists(args.target):
        main(args)
    else:
        print(WARN+'Error: Target file does not exist.')
