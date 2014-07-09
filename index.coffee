
crypto = require("crypto")

module.exports = (S3_BUCKET, S3_SECRET, callback) ->
	
	callback {} unless S3_BUCKET? and S3_SECRET?

	date = new Date()
	date.setFullYear(date.getFullYear() + 1)

	s3Policy =
		expiration: date.toISOString()
		conditions: [
			{ bucket: S3_BUCKET ? ''}
			["starts-with", "$Content-Type", ""],
			{ acl: "public-read" }
			{ success_action_status: '201' }
			['starts-with', '$key', '']			
		]

	
	# stringify and encode the policy
	stringPolicy = JSON.stringify(s3Policy)
	base64Policy = Buffer(stringPolicy, "utf-8").toString("base64")
	
	# sign the base64 encoded policy
	signature = crypto.createHmac("sha1", S3_SECRET ? '').update(new Buffer(base64Policy, "utf-8")).digest("base64")
	
	# build the results object
	s3Credentials =
		S3_POLICY: base64Policy
		S3_SIGNATURE: signature

	# send it back
	callback s3Credentials

	return