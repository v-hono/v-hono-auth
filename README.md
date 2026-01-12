# meiseayoung.hono_auth

Authentication and authorization library for v-hono-core framework.

## Features

- JWT (JSON Web Token) authentication with HS256/384/512 algorithms
- Bearer token authentication
- User session management
- Role-based permission system
- Menu/permission tree building

## Installation

```bash
v install meiseayoung.hono
v install meiseayoung.hono_auth
```

## Usage

### JWT Authentication

```v
import meiseayoung.hono
import meiseayoung.hono_auth
import meiseayoung.hono_middleware

fn main() {
    mut app := hono.Hono.new()
    secret := 'your-secret-key'

    // Protect routes with JWT middleware
    app.use('/api/*', hono_auth.jwt_middleware(hono_auth.JwtOptions{
        secret: secret
        alg: .hs256
    }))

    app.get('/api/profile', fn (mut c hono.Context) http.Response {
        payload := hono_auth.get_jwt_payload(c) or {
            return c.json('{"error":"No JWT payload"}')
        }
        return c.json('{"user":"${payload.sub}"}')
    })

    app.listen(':3000')
}
```

### Bearer Token Authentication

```v
import meiseayoung.hono
import meiseayoung.hono_auth

fn main() {
    mut app := hono.Hono.new()

    app.use('/api/*', hono_auth.bearer_auth(hono_auth.BearerAuthOptions{
        token: 'your-api-token'
    }))

    app.get('/api/data', fn (mut c hono.Context) http.Response {
        return c.json('{"data":"protected"}')
    })

    app.listen(':3000')
}
```

## Dependencies

- `meiseayoung.hono` - Core framework
- `meiseayoung.hono_middleware` - Cookie support for JWT

## License

MIT
