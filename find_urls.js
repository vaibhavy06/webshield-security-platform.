const fs = require('fs');
const path = require('path');
const dir = 'frontend/dist/assets';
fs.readdirSync(dir).forEach(f => {
  if(f.endsWith('.js')){
    const c = fs.readFileSync(path.join(dir,f),'utf8');
    const m = c.match(/https?:\/\/[^\/\"\']+/g);
    if(m) {
        const unique = [...new Set(m)];
        console.log(f, unique.filter(u => u.includes('webshield') || u.includes('localhost') || u.includes('pinggy')));
    }
  }
});
