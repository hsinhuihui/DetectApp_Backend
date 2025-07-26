const bcrypt = require('bcrypt');
const plain = '12345678';
const saltRounds = 10;

bcrypt.hash(plain, saltRounds, (err, hash) => {
  if (err) throw err;
  console.log('加密後密碼：', hash);
});
