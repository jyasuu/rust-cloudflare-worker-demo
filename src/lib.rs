use worker::*;
use serde::{Deserialize, Serialize};
use url::Url;
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: String,
}

#[derive(Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    scope: String,
}

#[derive(Serialize, Deserialize)]
struct UserSession {
    user: GitHubUser,
    access_token: String,
    expires_at: u64,
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    Router::new()
        .get_async("/", handle_root)
        .get_async("/auth/github", handle_github_auth)
        .get_async("/auth/github/callback", handle_github_callback)
        .get_async("/api/user", handle_get_user)
        .post_async("/api/logout", handle_logout)
        .run(req, env)
        .await
}

async fn handle_root(_req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    let html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>GitHub OAuth Demo</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .user-info { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .avatar { width: 64px; height: 64px; border-radius: 50%; margin-right: 15px; vertical-align: middle; }
        button { padding: 10px 20px; font-size: 16px; cursor: pointer; margin: 5px; }
        .login-btn { background: #333; color: white; border: none; border-radius: 5px; }
        .logout-btn { background: #dc3545; color: white; border: none; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>GitHub OAuth Demo</h1>
    <div id="app">
        <div id="login-section">
            <p>Click the button below to login with GitHub:</p>
            <button class="login-btn" onclick="loginWithGitHub()">Login with GitHub</button>
        </div>
        <div id="user-section" style="display: none;">
            <div class="user-info" id="user-info"></div>
            <button class="logout-btn" onclick="logout()">Logout</button>
        </div>
    </div>

    <script>
        async function checkAuth() {
            try {
                const response = await fetch('/api/user');
                if (response.ok) {
                    const user = await response.json();
                    showUserInfo(user);
                } else {
                    showLogin();
                }
            } catch (error) {
                console.error('Auth check failed:', error);
                showLogin();
            }
        }

        function showLogin() {
            document.getElementById('login-section').style.display = 'block';
            document.getElementById('user-section').style.display = 'none';
        }

        function showUserInfo(user) {
            document.getElementById('login-section').style.display = 'none';
            document.getElementById('user-section').style.display = 'block';
            
            const userInfo = document.getElementById('user-info');
            userInfo.innerHTML = `
                <img src="${user.avatar_url}" alt="Avatar" class="avatar">
                <div style="display: inline-block;">
                    <h3>${user.name || user.login}</h3>
                    <p><strong>Username:</strong> ${user.login}</p>
                    <p><strong>ID:</strong> ${user.id}</p>
                    ${user.email ? `<p><strong>Email:</strong> ${user.email}</p>` : ''}
                </div>
            `;
        }

        function loginWithGitHub() {
            window.location.href = '/auth/github';
        }

        async function logout() {
            try {
                await fetch('/api/logout', { method: 'POST' });
                showLogin();
            } catch (error) {
                console.error('Logout failed:', error);
            }
        }

        // Check authentication status on page load
        checkAuth();
    </script>
</body>
</html>
    "#;

    Response::from_html(html)
}

async fn handle_github_auth(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    match ctx.env.var("GITHUB_CLIENT_ID")
    {
        Ok(_) =>{
        },
        Err(err) =>{
            return Response::error(format!("GITHUB_CLIENT_ID:{err:}"), 500);
        },
    }
    match ctx.env.var("GITHUB_CLIENT_ID")
    {
        Ok(_) =>{
        },
        Err(err) =>{
            return Response::error(format!("GITHUB_REDIRECT_URI:{err:}"), 500);
        },
    }

    let client_id = ctx.env.var("GITHUB_CLIENT_ID")?.to_string();
    let redirect_uri = ctx.env.var("GITHUB_REDIRECT_URI")?.to_string();

    match Url::parse("https://github.com/login/oauth/authorize") {
        Ok(_) =>{
            
        },
        Err(err) =>{
            return Response::error(format!("Parse:{err:}"), 500);
        },
        
    }
    
    let mut auth_url = Url::parse("https://github.com/login/oauth/authorize")?;
    auth_url.query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", "user:email");

    Response::redirect(auth_url)
}

async fn handle_github_callback(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let url = req.url()?;
    let query_params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    
    let code = match query_params.get("code") {
        Some(code) => code,
        None => {
            let unknown_error = "unknown_error".to_string();
            let error = query_params.get("error").unwrap_or(&unknown_error);
            return Response::error(format!("GitHub OAuth error: {}", error), 400);
        }
    };

    // Exchange code for access token
    let access_token = match exchange_code_for_token(code, &ctx.env).await {
        Ok(var)=>{ var },
        Err(error)=>{
            return Response::error(format!("GitHub OAuth access token: {}", error), 400);
        },
    };
    
    // Get user info from GitHub
    let user = match get_github_user(&access_token).await {
        Ok(var)=>{ var },
        Err(error)=>{
            return Response::error(format!("GitHub OAuth get user: {}", error), 400);
        },
    };
    
    // Create session
    let session = UserSession {
        user,
        access_token,
        expires_at: js_sys::Date::now() as u64 + (24 * 60 * 60 * 1000), // 24 hours
    };
    
    let session_json = match serde_json::to_string(&session) {
        Ok(var)=>{ var },
        Err(error)=>{
            return Response::error(format!("GitHub OAuth json: {}", error), 400);
        },
    };

    let root_url = format!(
        "{}://{}",
        req.url()?.scheme(),
        req.url()?.host_str().unwrap_or("")
    );
    
    let mut headers = Headers::new();

    match headers.append("Set-Cookie", &format!(
        "session={}; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/",
        session_json
    )){
        Ok(_)=>{ },
        Err(error)=>{
            return Response::error(format!("GitHub OAuth set cookie: {}", error), 400);
        },
    };

    
    let html = format!(
    r#"
<!DOCTYPE html>
<html>
<head>
    <title>GitHub OAuth Login</title>
</head>
<body>
    <script>
        window.location.href = '{root_url}';
    </script>
</body>
</html>
    "#);

    let response = match Response::from_html(html)
    {
        Ok(var)=>{ var },
        Err(error)=>{
            return Response::error(format!("GitHub OAuth html: {}", error), 400);
        },
    };
    
    let response = response.with_headers(headers);
    
    Ok(response)
}

async fn handle_get_user(req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    match get_session_from_request(&req) {
        Some(session) => {
            if session.expires_at > js_sys::Date::now() as u64 {
                let response = match Response::from_json(&session.user) {
                    Ok(res) => {res},
                    Err(error) => {
                        return Response::error(format!("GitHub OAuth get user session: {}", error), 400);
                    },
                };
                
                let mut headers = Headers::new();

                let referer = match req.headers().get("Referer"){
                    Ok(res) => {res.or(Some(String::from(""))).unwrap()},
                    Err(error) => {
                        return Response::error(format!("GitHub OAuth get user: {}", error), 400);
                    },
                };

                if referer.contains("https://worker-demo.capsleo2000.workers.dev") ||
                    referer.contains("https://jyasuu.github.io") ||
                    referer.contains("gitpod.io")
                {
                    match headers.append("Access-Control-Allow-Origin", &referer){
                        Ok(_)=>{ },
                        Err(error)=>{
                            return Response::error(format!("GitHub OAuth cors: {}", error), 400);
                        },
                    };

                }
                let response  = response.with_headers(headers);
                Ok(response)
            } else {
                Response::error("Session expired", 401)
            }
        }
        None => Response::error("Not authenticated", 401),
    }
}

async fn handle_logout(_req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    let mut response = Response::ok("Logged out")?;
    response.headers_mut().set("Set-Cookie", 
        "session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/"
    )?;
    Ok(response)
}

async fn exchange_code_for_token(code: &str, env: &Env) -> Result<String> {
    let client_id = env.var("GITHUB_CLIENT_ID")?.to_string();
    let client_secret = env.var("GITHUB_CLIENT_SECRET")?.to_string();
    
    let req = Request::new_with_init(
        "https://github.com/login/oauth/access_token",
        RequestInit::new()
            .with_method(Method::Post)
            .with_headers({
                let mut headers = Headers::new();
                headers.set("Accept", "application/json")?;
                headers.set("Content-Type", "application/x-www-form-urlencoded")?;
                headers
            })
            .with_body(Some(wasm_bindgen::JsValue::from_str(&format!(
                "client_id={}&client_secret={}&code={}",
                client_id, client_secret, code
            ))))
    )?;
    
    let mut response = Fetch::Request(req).send().await?;
    let token_response: TokenResponse = response.json().await?;
    
    Ok(token_response.access_token)
}

async fn get_github_user(access_token: &str) -> Result<GitHubUser> {
    let req = Request::new_with_init(
        "https://api.github.com/user",
        RequestInit::new()
            .with_method(Method::Get)
            .with_headers({
                let mut headers = Headers::new();
                headers.set("Authorization", &format!("token {}", access_token))?;
                headers.set("User-Agent", "Cloudflare-Worker")?;
                headers
            })
    )?;
    
    let mut response = Fetch::Request(req).send().await?;
    let user: GitHubUser = response.json().await?;
    
    Ok(user)
}

fn get_session_from_request(req: &Request) -> Option<UserSession> {
    let cookie_header = req.headers().get("Cookie").ok().flatten()?;
    
    for cookie_pair in cookie_header.split(';') {
        let mut parts = cookie_pair.trim().splitn(2, '=');
        if let (Some(name), Some(value)) = (parts.next(), parts.next()) {
            if name == "session" {
                if let Ok(session) = serde_json::from_str::<UserSession>(value) {
                    return Some(session);
                }
            }
        }
    }
    
    None
}

mod test{

    #[test]
    fn test()
    {
        assert_eq!(true,true);
    }
    
}