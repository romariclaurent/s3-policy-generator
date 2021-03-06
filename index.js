// Generated by CoffeeScript 1.7.1
(function() {
  var crypto;

  crypto = require("crypto");

  module.exports = function(S3_BUCKET, S3_SECRET, callback) {
    var base64Policy, date, s3Credentials, s3Policy, signature, stringPolicy;
    if (!((S3_BUCKET != null) && (S3_SECRET != null))) {
      callback({});
    }
    date = new Date();
    date.setFullYear(date.getFullYear() + 1);
    s3Policy = {
      expiration: date.toISOString(),
      conditions: [
        {
          bucket: S3_BUCKET != null ? S3_BUCKET : ''
        }, ["starts-with", "$Content-Type", ""], {
          acl: "public-read"
        }, {
          success_action_status: '201'
        }, ['starts-with', '$key', '']
      ]
    };
    stringPolicy = JSON.stringify(s3Policy);
    base64Policy = Buffer(stringPolicy, "utf-8").toString("base64");
    signature = crypto.createHmac("sha1", S3_SECRET != null ? S3_SECRET : '').update(new Buffer(base64Policy, "utf-8")).digest("base64");
    s3Credentials = {
      S3_POLICY: base64Policy,
      S3_SIGNATURE: signature
    };
    callback(s3Credentials);
  };

}).call(this);
