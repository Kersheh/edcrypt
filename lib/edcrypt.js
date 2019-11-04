const { createReadStream, createWriteStream, unlinkSync } = require('fs');
const { extname } = require('path');
const { createGzip, createUnzip } = require('zlib');
const { createHash, randomBytes, createCipheriv, createDecipheriv } = require('crypto');
const { Transform } = require('stream');

class AppendInitVect extends Transform {
  constructor(initVect, opts) {
    super(opts);
    this.initVect = initVect;
    this.appended = false;
  }

  _transform(chunk, encoding, cb) {
    if(!this.appended) {
      this.push(this.initVect);
      this.appended = true;
    }
    
    this.push(chunk);
    cb();
  }
}

function _logAbort(msg) {
  console.error(msg);
  process.exit(1);
}

function _getCipherKey(password) {
  return createHash('sha256').update(password).digest();
}

function encrypt({ file, password }) {
  if(typeof file !== 'string') {
    _logAbort('Filename required to encrypt');
  }

  if(typeof password !== 'string') {
    _logAbort('Password required to encrypt');
  }

  const initVect = randomBytes(16);

  createReadStream(file)
    .on('error', err => _logAbort(`File '${file}' not found`))
    .pipe(createGzip())
    .pipe(createCipheriv('aes256', _getCipherKey(password), initVect))
    .pipe(new AppendInitVect(initVect))
    .pipe(createWriteStream(`${file}.enc`));
}

function decrypt({ file, password }) {
  if(typeof file !== 'string') {
    _logAbort('Filename required to decrypt');
  }

  if(extname(file) !== '.enc') {
    _logAbort(`File must of be of type '.enc'`);
  }

  if(typeof password !== 'string') {
    _logAbort('Password required to decrypt');
  }

  const filename = file.split('.enc')[0];
  let initVect;
  
  createReadStream(file, { end: 15 })
    .on('error', err => _logAbort(`File '${file}' not found`))
    .on('data', chunk => initVect = chunk)
    .on('close', () => {
      createReadStream(file, { start: 16 })
        .pipe(createDecipheriv('aes256', _getCipherKey(password), initVect))
        .pipe(createUnzip())
        .on('error', () => {
          unlinkSync(filename);
          _logAbort('Invalid password');
        })
        .pipe(createWriteStream(filename));
    });
}

module.exports = {
  encrypt,
  decrypt
};
