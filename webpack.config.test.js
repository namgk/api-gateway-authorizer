const config = require('./webpack.config');
config.module.rules.push(
  {
    test: /test\.js$/,
    use: 'mocha-loader',
    exclude: /node_modules/
  }
);
module.exports = config;