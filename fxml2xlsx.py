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
import traceback
import xml.dom.minidom

from datetime import datetime

try:
    from xlsxwriter.workbook import Workbook
except ImportError:
    print('''
Warning: xlsxwriter library is not installed, cannot output xlsx format.
Download it from: https://pypi.python.org/pypi/XlsxWriter ''')

try:
    import xml.etree.cElementTree as ET
except ImportError:
    print('Warning: Failed to import cElementTree, falling back to ElementTree')
    import xml.etree.ElementTree as ET


### Setup Stuff
if platform.system().lower() in ['linux', 'darwin']:
    INFO = "\033[1m\033[36m[*]\033[0m "
    WARN = "\033[1m\033[31m[!]\033[0m "
    BOLD = "\033[1m"
else:
    INFO = "[*] "
    WARN = "[!] "
    BOLD = ""


def print_info(msg):
    ''' Clears the current line and prints message '''
    sys.stdout.write(chr(27) + '[2K')
    sys.stdout.write('\r' + INFO + msg)
    sys.stdout.flush()


### Classes
class Finding(object):
    '''
    Holds data for a single Fortify finding, sortable by severity (rank)
    '''

    def __init__(self, **kwargs):
        self.category = kwargs.get('category', '').strip()      # <Category />
        self.severity = kwargs.get('severity', '').strip()      # <Folder />
        self.file_name = kwargs.get('file_name', '').strip()    # <FileName />
        self.file_path = kwargs.get('file_path', '').strip()    # <FilePath />
        self.line_start = kwargs.get('line_start', '').strip()  # <LineStart />
        self.target_function = kwargs.get('target_function', '').strip()
        self._ranks = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

    @property
    def rank(self):
        ''' Integer based on severity, used for sorting '''
        return self._ranks[self.severity.lower()]

    def __cmp__(self, other):
        ''' Allows us to call bult-in sorted() '''
        if self.rank < other.rank:
            return 1
        elif self.rank == other.rank:
            return 0
        else:
            return -1


class FortifyReport(object):
    ''' Python object based on the Fortify report xml data '''

    def __init__(self, file_path, debug=False):
        self.fname = file_path
        self.debug = debug
        try:
            self.tree = ET.parse(self.fname)
        except Exception as error:
            print(WARN+"ERROR: " + str(error))
            os._exit(1)
        self.doc = self.tree.getroot()
        self._findings = None
        self._ordered_findings = None
        self._severity_formats = None

    @property
    def findings(self):
        ''' Parse DOM and return list of Finding objects '''
        if self._findings is None:
            self._findings = {
                'critical': [], 'high': [], 'medium': [], 'low': []
            }
            self._generate_findings()
        return self._findings

    def _generate_findings(self):
        ''' Creates a list of findings based on a grouping '''
        issues = self.tree.findall(".//Issue")
        for index, issue in enumerate(issues):
            print_info("Parsing issue %d of %d ..." % (index + 1, len(issues)))
            severity = issue.findtext("Folder").strip().lower()
            primary = issue.find("Primary")
            finding = Finding(
                category=issue.findtext("Category"),
                severity=severity,
                file_name=primary.findtext("FileName"),
                file_path=primary.findtext("FilePath"),
                line_start=primary.findtext("LineStart"),
                target_function=primary.findtext("TargetFunction"),
            )
            if severity not in self._findings:
                self._findings[severity] = []
            self._findings[severity].append(finding)

    @property
    def ordered_findings(self):
        ''' Return a sorted master list of all findings '''
        if self._ordered_findings is None:
            master = []
            for risk_level in self.findings:
                master += self.findings[risk_level]
            self._ordered_findings = sorted(master)
        return self._ordered_findings

    def fix(self, output):
        ''' Fix DOM structure and output '''
        fout = sys.stdout if output is None else open(output, 'w')
        xml_dom = xml.dom.minidom.parse(self.fname)
        fout.write(xml_dom.toprettyxml())

    def to_csv(self, output):
        ''' Create a csv file based on findings '''
        fout = sys.stdout if output is None else open(output, 'w')
        fout.write("risk,filename,line,filepath\n")
        for vuln in self.ordered_findings:
            csv_line = (vuln.severity, vuln.file_name, vuln.line_start, 
                vuln.file_path, vuln.target_function,
            )
            fout.write("%s,%s,%s,%s,%s\n" % csv_line)

    def to_xlsx(self, output):
        ''' Create a Excel spreadsheet based on the findings '''
        fout = output if output is not None else 'FortifyReport.xlsx'
        if not fout.endswith('.xlsx'):
            fout += ".xlsx"
        workbook = Workbook(fout)
        self._write_xlsx_tabs(workbook)
        self._write_xlsx_master(workbook)
        print_info("Saved output to: " + BOLD + "%s\n" % fout)
        workbook.close()

    def _write_xlsx_tabs(self, workbook):
        '''
        Write findings to spreadsheet, each risk to a seperate worksheet
        '''
        for risk_level in self.findings:
            if not 0 < len(self.findings[risk_level]):
                continue
            print_info("Writing %s risk details to spreadsheet" % risk_level)
            worksheet = workbook.add_worksheet(risk_level.title())
            self._add_column_names(workbook, worksheet)
            self._resize_columns(worksheet, risk_level)
            for index, vuln in enumerate(self.findings[risk_level]):
                worksheet.write("A%d" % (index + 2,), vuln.category)
                worksheet.write("B%d" % (index + 2,), vuln.file_name)
                worksheet.write("C%d" % (index + 2,), vuln.line_start)
                worksheet.write("D%d" % (index + 2,), vuln.target_function)
                worksheet.write("E%d" % (index + 2,), vuln.file_path)

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

    def _resize_columns(self, worksheet, risk_level):
        ''' Adjust column width to longest string '''
        category_length = max(len(issue.category) for issue in self.findings[risk_level])
        worksheet.set_column('A:A', category_length)
        fname_length = max(len(issue.file_name) for issue in self.findings[risk_level])
        worksheet.set_column('B:B', fname_length)
        line_length = max(len(issue.line_start) for issue in self.findings[risk_level])
        worksheet.set_column('C:C', line_length + 10)  # Extra wiggle room for title
        tf_length = max(len(issue.target_function) for issue in self.findings[risk_level])
        worksheet.set_column('D:D', tf_length)
        fpath_length = max(len(issue.file_path) for issue in self.findings[risk_level])
        worksheet.set_column('E:E', fpath_length)

    def _write_xlsx_master(self, workbook):
        ''' Write an order list of all issues '''
        print_info("Writing master list to spreadsheet")
        worksheet = workbook.add_worksheet("Master")
        self._add_master_names(workbook, worksheet)
        self._resize_master(worksheet)
        for index, vuln in enumerate(self.ordered_findings):
            cell_format = self._severity_format(workbook, vuln.severity)
            severity_text = vuln.severity.title() + " Risk"
            worksheet.write("A%d" % (index + 2,), severity_text, cell_format)
            worksheet.write("B%d" % (index + 2,), vuln.category)
            worksheet.write("C%d" % (index + 2,), vuln.file_name)
            worksheet.write("D%d" % (index + 2,), vuln.line_start)
            worksheet.write("E%d" % (index + 2,), vuln.target_function)
            worksheet.write("F%d" % (index + 2,), vuln.file_path)

    def _add_master_names(self, workbook, worksheet):
        ''' Add master column names '''
        cell_format = workbook.add_format()
        cell_format.set_bold()
        cell_format.set_font_color('white')
        cell_format.set_bg_color('blue')
        worksheet.write("A1", "Risk Level", cell_format)
        worksheet.write("B1", "Category", cell_format)
        worksheet.write("C1", "File Name", cell_format)
        worksheet.write("D1", "Line Start", cell_format)
        worksheet.write("E1", "Target Function", cell_format)
        worksheet.write("F1", "File Path", cell_format)

    def _resize_master(self, worksheet):
        ''' Resize columns in the master tab to longest string '''
        worksheet.set_column('A:A', len("Critical Risk"))  # Longest severity string
        category_length = max(len(issue.category) for issue in self.ordered_findings)
        worksheet.set_column('B:B', category_length)
        fname_length = max(len(issue.file_name) for issue in self.ordered_findings)
        worksheet.set_column('C:C', fname_length)
        line_length = max(len(issue.line_start) for issue in self.ordered_findings)
        worksheet.set_column('D:D', line_length + 10)  # Extra wiggle room for title
        tf_length = max(len(issue.target_function) for issue in self.ordered_findings)
        worksheet.set_column('E:E', tf_length)
        fpath_length = max(len(issue.file_path) for issue in self.ordered_findings)
        worksheet.set_column('F:F', fpath_length)

    def _severity_format(self, workbook, severity):
        ''' Create format based on severity level '''
        cell_format = workbook.add_format()
        cell_format.set_bold()
        cell_format.set_font_color('white')
        if severity == 'critical': cell_format.set_bg_color('red')
        elif severity == 'high': cell_format.set_bg_color('orange')
        elif severity == 'medium': cell_format.set_bg_color('yellow')
        else: cell_format.set_bg_color('navy')
        return cell_format

    def __len__(self):
        ''' Return the total number of findings parsed from XML file '''
        return sum([len(self._findings[key]) for key in self._findings])


### Main Function
def main(args):
    ''' Call functions based on user args '''
    start = datetime.now()
    report = FortifyReport(args.input, args.debug)
    formats = {
        'xml': report.fix,
        'xlsx': report.to_xlsx,
        'csv': report.to_csv,
    }
    if args.format not in formats:
        print(WARN + 'Error: Output format not supported.')
    else:
        if args.output is not None and os.path.exists(args.output):
            print(WARN + "Warning: Overwriting file " + BOLD + args.output)
        formats[args.format](args.output)
    delta = datetime.now() - start
    if args.output is not None or args.format == 'xlsx':
        print_info("Completed in %f second(s)\n" % delta.total_seconds())


### CLI Code
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Convert Fortify reports to a friendly spreadsheet formats',
    )
    parser.add_argument('--version', '-v',
        action='version',
        version='%(prog)s v0.1'
    )
    parser.add_argument('--debug', '-d',
        action='store_true',
        help='enable debug stack traces',
        dest='debug',
    )
    parser.add_argument('--input', '-i',
        help='input Fortify report .xml file',
        dest='input',
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
    if os.path.exists(args.input) and os.path.isfile(args.input):
        main(args)
    else:
        print(WARN + 'Error: Target file does not exist.')
