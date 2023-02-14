import * as jose from 'jose'
import express from 'express'
import cookieParser from 'cookie-parser'

// create a public signature in node

const loginTemplate = () => `
	<body>
		<script src="/jose-4.11.4.js"></script>
		<script src="https://cdn.jsdelivr.net/npm/idb-keyval@6/dist/umd.js"></script>

		<form id='login' method='post' action='/login'>
			<input type='hidden' name='public_key'></input>
		</form>

		<script>
			async function login() {
				// generate a public and private key pair
				const { publicKey, privateKey } = await jose.generateKeyPair('ES256')
				const jwk = await jose.exportJWK(publicKey)
				
				// store the privateKey in idb
				await idbKeyval.set('private_key', privateKey)
				
				// send the public_key to the server
				document.forms.login.public_key.value = JSON.stringify(jwk)
				
				// submit the form
				document.forms.login.submit()
			}
		</script>

		<button type="button" onclick="login()">Login</button>
	</body>
`

const logoutTemplate = req => `
	<body>
		<script src="/jose-4.11.4.js"></script>
		<script src="https://cdn.jsdelivr.net/npm/idb-keyval@6/dist/umd.js"></script>

		<p>hello <span id='user_name'></span></p>
		<form method='post' action='/logout'>
			<button>Logout</button>
		</form>

		<script>
			async function main() {
				const privateKey = await idbKeyval.get('private_key')
				const sign_payload = Date.now()
				const jws = await new jose.CompactSign(
						new TextEncoder().encode(sign_payload),
					)
					.setProtectedHeader({ alg: 'ES256' })
					.sign(privateKey)
				
				const res = await fetch('/me', {
					headers: {
						sig: jws.toString()
					}
				})
				const json = await res.json()
				window.user_name.innerText = json.user
			}
			main()
		</script>
	</body>
`
	
express()
	.use(cookieParser('secr3t'))
	.use(express.urlencoded({ extended: true }))
	.use(express.static('static'))
	
	.use(function authMiddleware(req, res, next) {
		req.auth = req.signedCookies.auth
		next()
	})
	
	.get('/', (req, res) => {
		if (req.auth) {
			res.end(logoutTemplate(req))
		} else {
			res.end(loginTemplate())
		}
	})
	
	.post('/login', (req, res) => {
		// NOT SHOWN: authenticate joe@example.com
		const cookie = {
			user: 'joe@example.com',
			public_key: req.body.public_key,
		}
		console.log('setting cookie:', cookie)
		res.cookie('auth', cookie, { httpOnly: true, signed: true })
		res.redirect(301, '/')
	})
	
	.post('/logout', (req, res) => {
		console.log('clearing cookie')
		res.clearCookie('auth')
		res.redirect(301, '/')
	})
	
	.get('/me', async (req, res) => {
		// check the sig header
		const sig = req.headers['sig']
		const jwk = JSON.parse(req.auth.public_key)
		const publicKey = await jose.importJWK(jwk, 'ES256')
		const { payload } = await jose.compactVerify(sig, publicKey)
		
		// parse the signed time
		const time = Number(payload.toString())
		
		// ensure the time is within a 5 minute drift
		const now = Date.now()
		const fiveMin = 5 * 60 * 1000
		if (time < now - fiveMin || time > now + fiveMin) {
			throw new Error('Invalid signature')
		}
		
		const json = JSON.stringify({
			user: req.auth.user
		})
		res.end(json)
	})
	
	.listen(3001, () => {
		console.log(`> Running on http://localhost:3001`)
	})
