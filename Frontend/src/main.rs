use leptos::*;
use leptos_meta::*;
use leptos::spawn_local;
use serde::{Deserialize, Serialize};
use web_sys::{Request, RequestInit, RequestMode, Response, WebSocket, MessageEvent, CloseEvent};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use js_sys;

// --- Structs ---

/// AuthState stored in the root App component
#[derive(Clone, Debug, PartialEq)]
struct AuthState {
    token: String,
    username: String,
}

/// For login/register POST body
#[derive(Serialize, Clone)]
struct Credentials {
    username: String,
    password: String,
}

/// Expected response from /login or /register
#[derive(Deserialize, Clone, Debug)]
struct AuthResponse {
    token: String,
    username: String,
}

/// A chat message received from the WebSocket
#[derive(Deserialize, Clone, Debug, PartialEq)]
struct ChatMessage {
    #[serde(rename = "type")]
    msg_type: String, // "chat", "join", "leave"
    content: String,
    username: String,
    timestamp: String, // Keep it simple as a string
    #[serde(rename = "timeStr")]
    time_str: String,
}

/// A message sent to the WebSocket
#[derive(Serialize)]
struct ClientMessage {
    content: String,
}

// --- Constants ---

// Backend URL - matches your Go backend
const BACKEND_URL: &str = "http://localhost:5000";

// --- Components ---

/// The root component of the application
#[component]
fn App() -> impl IntoView {
    // Provides contexts for meta tags (like <Title>)
    provide_meta_context();

    // This signal holds the authentication state (token and username)
    // It's None if the user is not logged in.
    let auth_state = create_rw_signal(None::<AuthState>);

    view! {
        <Title text="TweetChat - Go + Leptos"/>
        
        // This Show component conditionally renders its children.
        // It shows <ChatPage> if auth_state is Some,
        // and <AuthPage> if auth_state is None.
        <Show
            when=move || auth_state.get().is_some()
            fallback=move || view! { <AuthPage set_auth=auth_state.write_only() /> }
        >
            // We can safely unwrap here because `when` check ensures it's Some
            <ChatPage auth=auth_state.get().unwrap() set_auth=auth_state.write_only() />
        </Show>
    }
}

/// Page for User Login and Registration
#[component]
fn AuthPage(set_auth: WriteSignal<Option<AuthState>>) -> impl IntoView {
    // Signals for form inputs
    let (login_username, set_login_username) = create_signal(String::new());
    let (login_password, set_login_password) = create_signal(String::new());
    let (reg_username, set_reg_username) = create_signal(String::new());
    let (reg_password, set_reg_password) = create_signal(String::new());
    
    // Signal for displaying error messages
    let error_message = create_rw_signal(None::<String>);

    // Helper to clear error
    let clear_error = move || error_message.set(None);

    // Helper to handle auth success
    let on_auth_success = move |resp: AuthResponse| {
        set_auth.set(Some(AuthState {
            token: resp.token,
            username: resp.username,
        }));
        clear_error();
    };

    // Helper to handle auth error
    let on_auth_error = move |err: String| {
        log::error!("Auth error: {}", err);
        error_message.set(Some("Login/Register failed. User might exist or password incorrect.".to_string()));
    };

    // Action for registration
    let register_action = create_action(move |(username, password): &(String, String)| {
        let creds = Credentials { username: username.clone(), password: password.clone() };
        let on_success = on_auth_success.clone();
        let on_error = on_auth_error.clone();
        async move {
            let opts = RequestInit::new();
            opts.set_method("POST");
            opts.set_mode(RequestMode::Cors);
            
            let body = serde_json::to_string(&creds).unwrap();
            opts.set_body(&JsValue::from_str(&body));
            
            let request = Request::new_with_str_and_init(&format!("{}/api/register", BACKEND_URL), &opts).unwrap();
            request.headers().set("Content-Type", "application/json").unwrap();
            
            let window = web_sys::window().unwrap();
            let resp_value: JsValue = JsFuture::from(window.fetch_with_request(&request)).await.unwrap();
            let resp: Response = resp_value.dyn_into().unwrap();
            
            if resp.ok() {
                let json: JsValue = JsFuture::from(resp.json().unwrap()).await.unwrap();
                let auth_resp: AuthResponse = serde_wasm_bindgen::from_value(json).unwrap();
                on_success(auth_resp);
            } else {
                on_error("Registration failed".to_string());
            }
        }
    });

    // Action for login
    let login_action = create_action(move |(username, password): &(String, String)| {
        let creds = Credentials { username: username.clone(), password: password.clone() };
        let on_success = on_auth_success.clone();
        let on_error = on_auth_error.clone();
        async move {
            let opts = RequestInit::new();
            opts.set_method("POST");
            opts.set_mode(RequestMode::Cors);
            
            let body = serde_json::to_string(&creds).unwrap();
            opts.set_body(&JsValue::from_str(&body));
            
            let request = Request::new_with_str_and_init(&format!("{}/api/login", BACKEND_URL), &opts).unwrap();
            request.headers().set("Content-Type", "application/json").unwrap();
            
            let window = web_sys::window().unwrap();
            let resp_value: JsValue = JsFuture::from(window.fetch_with_request(&request)).await.unwrap();
            let resp: Response = resp_value.dyn_into().unwrap();
            
            if resp.ok() {
                let json: JsValue = JsFuture::from(resp.json().unwrap()).await.unwrap();
                let auth_resp: AuthResponse = serde_wasm_bindgen::from_value(json).unwrap();
                on_success(auth_resp);
            } else {
                on_error("Login failed".to_string());
            }
        }
    });

    // Submit handlers
    let on_register = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        clear_error();
        register_action.dispatch((reg_username.get(), reg_password.get()));
    };
    
    let on_login = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        clear_error();
        login_action.dispatch((login_username.get(), login_password.get()));
    };

    view! {
        <div class="flex items-center justify-center min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
            <div class="w-full max-w-4xl mx-4">
                // Error message display
                <Show when=move || error_message.get().is_some() fallback=|| ()>
                    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg relative mb-6" role="alert">
                        <span class="block sm:inline">{error_message.get().unwrap()}</span>
                    </div>
                </Show>

                <div class="grid md:grid-cols-2 gap-8">
                    // Login Form
                    <form class="bg-white shadow-xl rounded-2xl p-8 border border-gray-200" on:submit=on_login>
                        <h2 class="text-3xl font-bold text-center text-gray-800 mb-8">Login</h2>
                        <div class="mb-6">
                            <label class="block text-gray-700 text-sm font-bold mb-2" for="login_user">Username</label>
                            <input class="shadow-sm appearance-none border rounded-lg w-full py-3 px-4 text-gray-700 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500"
                                id="login_user" type="text" placeholder="Username"
                                on:input=move |ev| set_login_username.set(event_target_value(&ev))
                                prop:value=login_username />
                        </div>
                        <div class="mb-8">
                            <label class="block text-gray-700 text-sm font-bold mb-2" for="login_pass">Password</label>
                            <input class="shadow-sm appearance-none border rounded-lg w-full py-3 px-4 text-gray-700 mb-3 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500"
                                id="login_pass" type="password" placeholder="******************"
                                on:input=move |ev| set_login_password.set(event_target_value(&ev))
                                prop:value=login_password />
                        </div>
                        <div class="flex items-center justify-center">
                            <button class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg focus:outline-none focus:shadow-outline transition duration-300" type="submit">
                                Sign In
                            </button>
                        </div>
                    </form>

                    // Register Form
                    <form class="bg-white shadow-xl rounded-2xl p-8 border border-gray-200" on:submit=on_register>
                        <h2 class="text-3xl font-bold text-center text-gray-800 mb-8">Register</h2>
                        <div class="mb-6">
                            <label class="block text-gray-700 text-sm font-bold mb-2" for="reg_user">Username</label>
                            <input class="shadow-sm appearance-none border rounded-lg w-full py-3 px-4 text-gray-700 leading-tight focus:outline-none focus:ring-2 focus:ring-green-500"
                                id="reg_user" type="text" placeholder="New Username"
                                on:input=move |ev| set_reg_username.set(event_target_value(&ev))
                                prop:value=reg_username />
                        </div>
                        <div class="mb-8">
                            <label class="block text-gray-700 text-sm font-bold mb-2" for="reg_pass">Password</label>
                            <input class="shadow-sm appearance-none border rounded-lg w-full py-3 px-4 text-gray-700 mb-3 leading-tight focus:outline-none focus:ring-2 focus:ring-green-500"
                                id="reg_pass" type="password" placeholder="******************"
                                on:input=move |ev| set_reg_password.set(event_target_value(&ev))
                                prop:value=reg_password />
                        </div>
                        <div class="flex items-center justify-center">
                            <button class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-4 rounded-lg focus:outline-none focus:shadow-outline transition duration-300" type="submit">
                                Register
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    }
}

/// The main Chat Page, shown after login
#[component]
fn ChatPage(auth: AuthState, set_auth: WriteSignal<Option<AuthState>>) -> impl IntoView {
    // --- State Signals ---
    
    // Forms for creating/joining servers
    let (new_server_name, set_new_server_name) = create_signal(String::new());
    let (new_server_pass, set_new_server_pass) = create_signal(String::new());
    let (join_server_name, set_join_server_name) = create_signal(String::new());
    let (join_server_pass, set_join_server_pass) = create_signal(String::new());

    // Form for sending a message
    let (message_to_send, set_message_to_send) = create_signal(String::new());
    
    // List of messages in the current chat
    let messages = create_rw_signal(Vec::<ChatMessage>::new());
    
    // General error/success messages
    let form_message = create_rw_signal(None::<String>);
    
    // Current server state
    let current_server = create_rw_signal(None::<String>);
    
    // WebSocket connection state
    let ws_connection = create_rw_signal(None::<WebSocket>);

    // Handler for logging out
    let on_logout = move |_| {
        // Close WebSocket if connected
        if let Some(ws) = ws_connection.get() {
            ws.close().ok();
        }
        set_auth.set(None); // Clear auth state
    };
    
    // Function to connect to WebSocket
    let connect_to_server = {
        let token = auth.token.clone();
        let auth_clone = auth.clone();
        let messages = messages.clone();
        let form_message = form_message.clone();
        let current_server = current_server.clone();
        let ws_connection = ws_connection.clone();
        let set_join_server_name = set_join_server_name.clone();
        let set_join_server_pass = set_join_server_pass.clone();
        
        move |server_name: String, password: String| {
            // Close existing connection
            if let Some(ws) = ws_connection.get() {
                ws.close().ok();
            }
            
            let url = format!("ws://localhost:5000/ws/{}?token={}&password={}", 
                server_name, token, password);
            
            log::info!("Connecting to: {}", url);
            
            match WebSocket::new(&url) {
                Ok(ws) => {
                    let messages_clone = messages.clone();
                    let auth_username = auth_clone.username.clone();
                    
                    // Setup message handler
                    let onmessage_callback = Closure::wrap(Box::new(move |e: MessageEvent| {
                        // Get the message data as a string
                        let text = e.data().as_string();
                        
                        if let Some(text) = text {
                            log::info!("Received message: {}", text);
                            
                            match serde_json::from_str::<ChatMessage>(&text) {
                                Ok(msg) => {
                                    log::info!("Successfully parsed message from {}: {}", msg.username, msg.content);
                                    messages_clone.update(|msgs| {
                                        msgs.push(msg);
                                    });
                                }
                                Err(err) => {
                                    log::error!("Failed to parse message '{}': {:?}", text, err);
                                }
                            }
                        } else {
                            log::error!("Could not extract message text from WebSocket event");
                        }
                    }) as Box<dyn FnMut(MessageEvent)>);
                    
                    ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
                    onmessage_callback.forget();
                    
                    // Setup close handler
                    let onclose_callback = Closure::wrap(Box::new(move |e: CloseEvent| {
                        log::info!("WebSocket closed: {:?}", e.reason());
                        form_message.set(Some("Disconnected from server".to_string()));
                    }) as Box<dyn FnMut(CloseEvent)>);
                    
                    ws.set_onclose(Some(onclose_callback.as_ref().unchecked_ref()));
                    onclose_callback.forget();
                    
                    // Setup error handler
                    let onerror_callback = Closure::wrap(Box::new(move |_| {
                        log::error!("WebSocket error");
                        form_message.set(Some("Error connecting to server".to_string()));
                    }) as Box<dyn FnMut(JsValue)>);
                    
                    ws.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
                    onerror_callback.forget();
                    
                    // Setup open handler
                    let messages_clone = messages.clone();
                    let auth_username_clone = auth_username.clone();
                    let server_name_clone = server_name.clone();
                    let form_message_clone = form_message.clone();
                    let token_clone = token.clone();
                    let onopen_callback = Closure::wrap(Box::new(move |_| {
                        log::info!("WebSocket connected");
                        form_message_clone.set(Some(format!("Connected to server '{}'", server_name_clone)));
                        
                        // Fetch chat history
                        let messages_for_history = messages_clone.clone();
                        let server_name_for_history = server_name_clone.clone();
                        let token_for_history = token_clone.clone();
                        
                        spawn_local(async move {
                            let url = format!("{}/api/chat/history?server={}&limit=100", BACKEND_URL, server_name_for_history);
                            log::info!("Loading chat history from: {}", url);
                            
                            let opts = RequestInit::new();
                            opts.set_method("GET");
                            opts.set_mode(RequestMode::Cors);
                            
                            let headers = web_sys::Headers::new().unwrap();
                            headers.set("Authorization", &format!("Bearer {}", token_for_history)).unwrap();
                            opts.set_headers(&headers);
                            
                            let request = Request::new_with_str_and_init(&url, &opts).unwrap();
                            let window = web_sys::window().unwrap();
                            
                            match JsFuture::from(window.fetch_with_request(&request)).await {
                                Ok(resp_value) => {
                                    let resp: Response = resp_value.dyn_into().unwrap();
                                    
                                    if resp.ok() {
                                        match JsFuture::from(resp.json().unwrap()).await {
                                            Ok(json) => {
                                                // Parse the response
                                                match js_sys::Reflect::get(&json, &JsValue::from_str("messages")) {
                                                    Ok(msgs_value) => {
                                                        if let Some(messages_array) = msgs_value.dyn_ref::<js_sys::Array>() {
                                                            let mut loaded_messages = Vec::new();
                                                            for i in 0..messages_array.length() {
                                                                if let Some(msg_obj) = messages_array.get(i).dyn_ref::<js_sys::Object>() {
                                                                    let id = js_sys::Reflect::get(msg_obj, &JsValue::from_str("id")).ok()
                                                                        .and_then(|v| v.as_f64()).unwrap_or(0.0);
                                                                    let username = js_sys::Reflect::get(msg_obj, &JsValue::from_str("username")).ok()
                                                                        .and_then(|v| v.as_string()).unwrap_or_default();
                                                                    let content = js_sys::Reflect::get(msg_obj, &JsValue::from_str("content")).ok()
                                                                        .and_then(|v| v.as_string()).unwrap_or_default();
                                                                    let msg_type = js_sys::Reflect::get(msg_obj, &JsValue::from_str("messageType")).ok()
                                                                        .and_then(|v| v.as_string()).unwrap_or_default();
                                                                    let time_str = js_sys::Reflect::get(msg_obj, &JsValue::from_str("timeStr")).ok()
                                                                        .and_then(|v| v.as_string()).unwrap_or_default();
                                                                    
                                                                    let timestamp = js_sys::Reflect::get(msg_obj, &JsValue::from_str("timestamp")).ok()
                                                                        .and_then(|v| {
                                                                            if v.is_string() {
                                                                                v.as_string()
                                                                            } else {
                                                                                Some(format!("{:?}", v))
                                                                            }
                                                                        }).unwrap_or_default();
                                                                    
                                                                    let chat_msg = ChatMessage {
                                                                        msg_type: if msg_type.is_empty() { "chat".to_string() } else { msg_type },
                                                                        username,
                                                                        content,
                                                                        timestamp,
                                                                        time_str: if time_str.is_empty() { "-".to_string() } else { time_str },
                                                                    };
                                                                    
                                                                    loaded_messages.push(chat_msg);
                                                                }
                                                            }
                                                            
                                                            messages_for_history.update(|msgs| {
                                                                *msgs = loaded_messages;
                                                            });
                                                            
                                                            log::info!("Loaded {} messages from history", messages_array.length());
                                                        }
                                                    }
                                                    Err(_) => log::warn!("Failed to get messages from history response"),
                                                }
                                            }
                                            Err(err) => {
                                                log::error!("Failed to parse history JSON: {:?}", err);
                                            }
                                        }
                                    } else {
                                        log::error!("Failed to load chat history: {:?}", resp.status());
                                    }
                                }
                                Err(err) => {
                                    log::error!("Failed to fetch chat history: {:?}", err);
                                }
                            }
                        });
                    }) as Box<dyn FnMut(JsValue)>);
                    
                    ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
                    onopen_callback.forget();
                    
                    ws_connection.set(Some(ws));
                    current_server.set(Some(server_name));
                    set_join_server_name.set(String::new());
                    set_join_server_pass.set(String::new());
                }
                Err(err) => {
                    log::error!("Failed to create WebSocket: {:?}", err);
                    form_message.set(Some("Failed to connect to server".to_string()));
                }
            }
        }
    };
    
    // Handler for joining a server
    let on_join_server = {
        let join_server_name = join_server_name.clone();
        let join_server_pass = join_server_pass.clone();
        let connect_fn = connect_to_server.clone();
        
        move |ev: ev::SubmitEvent| {
            ev.prevent_default();
            let server_name = join_server_name.get();
            let password = join_server_pass.get();
            
            if server_name.is_empty() || password.is_empty() {
                form_message.set(Some("Please enter server name and password".to_string()));
                return;
            }
            
            // Clear messages when joining new server
            messages.set(Vec::new());
            
            connect_fn(server_name, password);
        }
    };
    
    // Handler for sending messages
    let on_send_message = {
        let message_to_send = message_to_send.clone();
        let set_message_to_send = set_message_to_send.clone();
        let ws_connection = ws_connection.clone();
        let current_server = current_server.clone();
        let form_message = form_message.clone();
        
        move |ev: ev::SubmitEvent| {
            ev.prevent_default();
            let msg = message_to_send.get();
            
            if msg.is_empty() {
                return;
            }
            
            if current_server.get().is_none() {
                form_message.set(Some("Please join a server first".to_string()));
                return;
            }
            
            if let Some(ws) = ws_connection.get() {
                let client_msg = ClientMessage { content: msg };
                if let Ok(json) = serde_json::to_string(&client_msg) {
                    if let Err(err) = ws.send_with_str(&json) {
                        log::error!("Failed to send message: {:?}", err);
                        form_message.set(Some("Failed to send message".to_string()));
                    } else {
                        set_message_to_send.set(String::new());
                    }
                }
            } else {
                form_message.set(Some("Not connected to a server".to_string()));
            }
        }
    };

    // --- Render ---

    view! {
        <div class="flex h-screen bg-gray-100">
            // --- Sidebar (Forms) ---
            <div class="w-full md:w-1/3 lg:w-1/4 bg-white shadow-lg p-6 overflow-y-auto">
                <div class="flex justify-between items-center mb-6">
                    <h1 class="text-2xl font-bold text-gray-800">TweetChat</h1>
                    <button
                        on:click=on_logout
                        class="text-sm text-red-500 hover:text-red-700 font-medium"
                    >
                        Logout
                    </button>
                </div>
                <p class="text-gray-600 mb-6">Welcome, <span class="font-bold">{auth.username.clone()}</span></p>

                // Form Message Display
                <Show when=move || form_message.get().is_some() fallback=|| ()>
                    <div class="bg-blue-100 text-blue-800 p-3 rounded-lg mb-6 text-sm">
                        {form_message.get().unwrap()}
                    </div>
                </Show>

                // Create Server Form
                <form class="mb-8">
                    <h3 class="text-lg font-semibold text-gray-700 mb-4">Create Server</h3>
                    <input class="shadow-sm border rounded-lg w-full py-2 px-3 text-gray-700 mb-3"
                        type="text" placeholder="New Server Name"
                        on:input=move |ev| set_new_server_name.set(event_target_value(&ev))
                        prop:value=new_server_name />
                    <input class="shadow-sm border rounded-lg w-full py-2 px-3 text-gray-700 mb-3"
                        type="password" placeholder="New Server Password"
                        on:input=move |ev| set_new_server_pass.set(event_target_value(&ev))
                        prop:value=new_server_pass />
                    <button class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-lg" type="submit">
                        Create
                    </button>
                </form>

                // Join Server Form
                <form on:submit=on_join_server>
                    <h3 class="text-lg font-semibold text-gray-700 mb-4">Join Server</h3>
                    <input class="shadow-sm border rounded-lg w-full py-2 px-3 text-gray-700 mb-3"
                        type="text" placeholder="Server Name"
                        on:input=move |ev| set_join_server_name.set(event_target_value(&ev))
                        prop:value=join_server_name />
                    <input class="shadow-sm border rounded-lg w-full py-2 px-3 text-gray-700 mb-3"
                        type="password" placeholder="Server Password"
                        on:input=move |ev| set_join_server_pass.set(event_target_value(&ev))
                        prop:value=join_server_pass />
                    <button class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg" type="submit">
                        Join
                    </button>
                </form>
                
                // Show current server info
                <Show when=move || current_server.get().is_some() fallback=|| ()>
                    <div class="mt-4 p-3 bg-gray-50 rounded-lg">
                        <p class="text-sm text-gray-600">Current Server:</p>
                        <p class="font-semibold text-gray-800">{current_server.get().unwrap()}</p>
                    </div>
                </Show>
            </div>

            // --- Main Chat Area ---
            <div class="flex-1 flex flex-col h-screen">
                // Chat Window
                <div id="chat-window" class="flex-1 p-6 overflow-y-auto space-y-4">
                    // Iterate over messages and display them
                    <For
                        each=move || messages.get()
                        key=|msg| format!("{}-{}", msg.timestamp, msg.username)
                        children=move |msg| {
                            let is_mine = msg.username == auth.username;
                            let is_system = msg.msg_type == "join" || msg.msg_type == "leave";

                            if is_system {
                                view! {
                                    <div class="text-center text-gray-500 text-sm italic message-enter">
                                        {msg.content}
                                    </div>
                                }
                            } else {
                                view! {
                                    <div class="flex message-enter" class:justify-end=is_mine>
                                        <div class="max-w-xs lg:max-w-md">
                                            <div class="font-bold text-sm"
                                                 class:text-blue-600=is_mine
                                                 class:text-gray-700=!is_mine
                                                 class:text-right=is_mine
                                            >
                                                {if is_mine { "You".to_string() } else { msg.username.clone() }}
                                                <span class="text-xs text-gray-400 ml-2">{msg.time_str}</span>
                                            </div>
                                            <div class="px-4 py-2 rounded-xl shadow"
                                                 class:bg-blue-500=is_mine
                                                 class:text-white=is_mine
                                                 class:bg-white=!is_mine
                                                 class:text-gray-800=!is_mine
                                            >
                                                {msg.content}
                                            </div>
                                        </div>
                                    </div>
                                }
                            }
                        }
                    />
                </div>

                // Message Input Form
                <form class="p-6 bg-white shadow-md" on:submit=on_send_message>
                    <div class="flex space-x-4">
                        <input class="flex-1 shadow-sm border rounded-lg w-full py-3 px-4 text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
                            type="text"
                            placeholder="Type a message..."
                            on:input=move |ev| set_message_to_send.set(event_target_value(&ev))
                            prop:value=message_to_send
                        />
                        <button class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-lg focus:outline-none focus:shadow-outline" type="submit">
                            Send
                        </button>
                    </div>
                </form>
            </div>
        </div>
    }
}

// --- Main ---

fn main() {
    // Setup logging
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();
    
    log::info!("TweetChat app started");
    
    // Mount the <App> component to the <body>
    mount_to_body(App);
}