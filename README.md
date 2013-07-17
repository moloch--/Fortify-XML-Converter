Fortify-XML-Converter
=====================

Convert Fortify XML documents to Excel spreadsheets.


Usage
=======
```
usage: fxml2xlsx.py [-h] [--version] --target TARGET [--output OUTPUT]
                    [--format FORMAT]

Convert Fortify reports to a friendly spreadsheet formats

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --target TARGET, -t TARGET
                        target Fortify report .xml file
  --output OUTPUT, -o OUTPUT
                        ouput file (default: stdout)
  --format FORMAT, -f FORMAT
                        ouptut format can be: xml, xlsx or csv (default: xlsx)
```