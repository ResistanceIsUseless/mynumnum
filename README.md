# mynumnum
My Enumeration Script

mynumnum is a simple enumeration script inspired from the countless other recon scripts out there, usually in relation to OSCP Exams.I wanted my script to be configurable by the user to easily add or disable new options. 

## How

The script uses libnmap as a foundtation for interacting with nmap and kicking of and parsing scan results. Then based off what scan finds it will check against the services dictionary and depending on what is defined there run addtional nmap scripts or preconfigured shell commands. 

## Why

Other recon scripts are too much work to disable options or add new options.

## Enhancements

- Make all subprocess calls multiprocressing.
- Add reporting options maybe with some parsing and pretty visuals.
- Create install to automatically add programs and wordlists
- Integrate with my web enumeration script
