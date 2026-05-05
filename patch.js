const fs = require('fs');
const path = require('path');
const file1 = path.join(__dirname, 'webshield-frontend', 'dist', 'assets', 'index-patched.js');
const file2 = path.join(__dirname, 'webshield-frontend', 'dist', 'assets', 'index-B2scnErZ.js');

function patchFile(file) {
    if (fs.existsSync(file)) {
        let content = fs.readFileSync(file, 'utf8');
        let newContent = content.replace(/https:\/\/curly-ties-sort\.loca\.lt/g, 'https://webshield-security-platform.vercel.app');
        newContent = newContent.replace(/http:\/\/localhost:8000/g, 'https://webshield-security-platform.vercel.app');
        fs.writeFileSync(file, newContent, 'utf8');
        console.log('Patched ' + file);
    }
}

patchFile(file1);
patchFile(file2);
