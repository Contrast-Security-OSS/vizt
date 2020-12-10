# README #

VIZT is a command line tool for visualizing Contrast trace XML exports.

### Setup

```
pip3 install .
```

### Example

Print HTTP request data and trace propagation:

```
vizt ~/Downloads/vulnerabilities2020-04-25.xml
```

Include stack traces in the output:

```
vizt ~/Downloads/vulnerabilities2020-04-25.xml -s
```
