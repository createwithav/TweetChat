use leptos::*;
use leptos_meta::*;
use serde::{Deserialize, Serialize};
use web_sys::{Request, RequestInit, RequestMode, Response};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

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

    // Handler for logging out
    let on_logout = move |_| {
        set_auth.set(None); // Clear auth state
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
                <form>
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
                <form class="p-6 bg-white shadow-md">
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