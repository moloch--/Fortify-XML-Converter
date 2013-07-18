Fortify-XML-Converter
=====================

Convert Fortify XML documents to useful formats.

* GPLv2
* Outputs xlsx, csv, or pretty xml
* Parses DOM
* Xml and csv outputs are pipe-able

Usage
=======
```
usage: fxml2xlsx.py [-h] [--version] [--debug] --input INPUT [--output OUTPUT]
                    [--format FORMAT]

Convert Fortify reports to a friendly spreadsheet formats

optional arguments:
  -h, --help            show this help message and exit
  --version, -v         show program's version number and exit
  --debug, -d           enable debug stack traces
  --input INPUT, -i INPUT
                        input Fortify report .xml file
  --output OUTPUT, -o OUTPUT
                        ouput file (default: stdout)
  --format FORMAT, -f FORMAT
                        ouptut format can be: xml, xlsx, or csv (default:
                        xlsx)
```
