---
title: Asian Cyber Security Challenge 2021 | Forensics Writeup | Nyong Coin, BitLocker Artifact
author:
  name: n3ddih
  link: https://github.com/n3ddih
date: 2021-09-22 23:20:00 +0700
categories: [CTF, Forensics Challenges]
tags: [writeups, forensics, acsc21]
mermaid: true
---

# Nyong Coin

## Description
- Download file: [link](https://drive.google.com/file/d/1F0-26SjSeCoixKtSY0E0keBFzsOVkRTd/view?usp=sharing)

```
'Kim' is the CEO of a cryptocurrency exchange 'A'. 
He asked the management team for the full transaction history of 'NYONG coin' traded in a specific period.
And here is 'Lee', a member of the management team who hates 'Kim', delivered a maliciously manipulated transaction history to 'Kim' in a USB.
Analyze the USB and find one manipulated transaction in there!
Flag: ACSC{lowercase(MANIPULATED_TRANSACTION_ID)}
```

## Solution

### Brief (2 ways)

#### 1. Using tools

1. Using `Autopsy` to identify and carve deleted `xlsx` file from image file.
2. The deleted file will be similar to 1 file in the main space -> identify that.
3. Text diff 2 files to find the differences. The difference row is the answer

#### 2. Using knowledge

1. History to data inserted is preserved in `xl/sharedStrings.xml` (*no log formatted strings such as `date, currency, scientific, etc.`*)
2. `PhoneticPr` attribute is used to provide a phonetic hint for a string, only generate when **data is typed**, not **Copy&Paste**

### Details

#### 1. Using tools

The downloaded file has a `E01` extensions, which indicates an image dump from NetWitness.

```console
$ file NyongCoin.E01
NyongCoin.E01: EWF/Expert Witness/EnCase image file format
```

These file can be viewed and analysed using tools like `FTK Imager`, `Autopsy` or `ProDiscover`.

> In my case, I noticed hex data of a xlsx file in the unallocated space in FTK Imager but decided not to carve the file out (outstanding move 🤡). Therefore I didn't finnish the challlenge.

To solve the challenge (or any other image forensics challenges), best use tools is `Autopsy`.

- After import image to `autopsy`, go to **CarvedFiles** then export xlsx files (*the data in 2 files are the same so take 1 file only*).

![image](https://user-images.githubusercontent.com/61876488/147463882-48bd85f0-7096-476e-84ce-64ea53c82fd0.png)

- Identify the original file by checking the fist row data of every files.

- Go to [TextCompare.org](https://www.textcompare.org/excel/), upload the exported file (*carved file*) and the original file and then compare.

![image](https://user-images.githubusercontent.com/61876488/147463890-9e34a2c7-815f-4159-aa15-fb6c75336d0c.png)

The answer is: `8d77a554-dc64-478c-b093-da4493a8534d`

> Flag: ACSC{8d77a554-dc64-478c-b093-da4493a8534d}

#### 2. Using knowledge

- **Extract** all xlsx file as zip to a folder then Grep `PhoneticPr` in all **sharedString.xml** files.

```console
$ for file in `find . -name sharedStrings.xml`;do grep -Hoi "phoneticPr" $file;done
./20200715132932_20200816181652/xl/sharedStrings.xml:phoneticPr
```

- Finding the id (*you can just view in text editor*):

```console
$ grep -Eo "phoneticPr.*$" ./20200715132932_20200816181652/xl/sharedStrings.xml
phoneticPr fontId="1" type="noConversion"/></si><si><t>8d77a554-dc64-478c-b093-da4493a8534d</t><phoneticPr fontId="1" type="noConversion"/></si></sst>
```

# BitLocker Artifact

## Description

- Download file: [link](https://drive.google.com/file/d/1kqYvfr3m0vihigvarV3xRBeuGEOTDZYB/view?usp=sharing)

```
Get the datetime that C drive was encrypted by BitLocker!

Start: When the BitLocker Wizard was run (UTC+0, YYYY-MM-DD_HH:MM:SS)
End: When encryption was completed by BitLocker (UTC+0, YYYY-MM-DD_HH:MM:SS)

Flag: ACSC{Start_End}
ex: ACSC{2021-05-06_12:00:01_2021-05-06_12:53:11}
```

## Solution

### Brief

The target is to identify the **start** and **end** timestamp of Bitlocker in registry hives.

Refer to [this tweet](https://twitter.com/0gtweet/status/1418322629996564480), to view the timestamp, we need to go to `\SYSTEM\CurrentControlSet\Control\FVEStats\`.

The start time is `OsvEncryptInit` and end time gonna be `OsvEncryptComplete`.

### Details

To view the registry, use `Registry Viewer` of **AccessData** or `Registry Explorer/RECmd` of [**ericzimmerman**](https://ericzimmerman.github.io/#!index.md).

Open **SYSTEM** file in the tool (*In my case it's `Registry Viewer`*). Locate to `\SYSTEM\ControlSet001\Control\FVEStats\`

![image](https://user-images.githubusercontent.com/61876488/147464004-78d0e6c5-1c18-485e-8c42-e32ca7279f44.png)

- **Start time**: **132741897867405652**
- **End time**: **132741901078561213**

To convert windows timestamp to UTC time

```PowerShell
PS C:\> [datetime]::FromFileTimeUTC("132741897867405652")
Monday, August 23, 2021 10:56:26 AM

PS C:\> [datetime]::FromFileTimeUTC("132741901078561213")
Monday, August 23, 2021 11:01:47 AM
```
