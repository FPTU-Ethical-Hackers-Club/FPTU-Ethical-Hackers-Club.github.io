---
title: FPTU SecAthon 2020 | Forensics Writeup | FRS301
author:
  name: n3ddih
  link: https://github.com/n3ddih
date: 2020-10-21 16:35:00 +0700
categories: [CTF, Forensics Challenges]
tags: [writeups, forensics, fusec20]
mermaid: true
---

# FRS301

## Description

Download file: [link](yellow_dot.pdf)

[Machine Identification Code](https://en.wikipedia.org/wiki/Machine_Identification_Code)

## Solution

### Brief

1. Convert the pdf files into images using `pdftoppm`
2. Use `deda` to extract informations from images
3. Grep serial number then extract data from that

### Details

- convert pdf to images

```console
$ pdftoppm -png yellow_dot.pdf output
```

- `deda_parse_print` to extract information from yellow dot

- 1 file output example:

```console
$ deda_parse_print yellow_dot-1.png
Detected pattern 4


_|0|1|2|3|4|5|6|7
0|
1|.
2|.
3|. .     . .   .
4|    . .   .
5|  .         . .
6|.
7|.
8|.     .     .
9|        .   . .
0|        .   . .
1|        .   . .
2|.           . .
3|.
4|        .   . .
5|  .   .   .
        37 dots.



<TDM of Pattern 4 at 0.00 x -0.00 inches>
Decoded:
        manufacturer: Epson
        serial: -775267-
        timestamp: 2018-11-11 11:11:00
        raw: 0000775267000018111111030011
        minutes: 11
        hour: 11
        day: 11
        month: 11
        year: 18
        unknown1: 00
        unknown3: 00
        unknown4: 00
        unknown5: 00
        printer: 00775267
```

- Final script:

```console
$ for file in `find . -name "*.png"`;do echo -n $(deda_parse_print $file | grep serial | grep -Eo [0-9]{6}) | sed 's/\(..\)/\1 /g' | awk '{printf "%c%c%c",$1,$2,$3}';done
```

