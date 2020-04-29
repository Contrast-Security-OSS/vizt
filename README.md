# README #

VIZT is a command line tool for visualizing Contrast trace XML exports.

### Example

Print HTTP request data and trace propagation:

```
python3 vizt.py ~/Downloads/vulnerabilities2020-04-25.xml
```

Include stack traces in the output:

```
python3 vizt.py ~/Downloads/vulnerabilities2020-04-25.xml -s
```
