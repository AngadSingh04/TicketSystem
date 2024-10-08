package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"

    "github.com/go-redis/redis/v8"
    "github.com/gorilla/mux"
    "github.com/jackc/pgx/v5"
    "golang.org/x/crypto/bcrypt"
    "github.com/rs/cors"
)

var ctx = context.Background()

// Database connection function
func connectDB() (*pgx.Conn, error) {
    conn, err := pgx.Connect(ctx, "postgres://postgres:Angad@04@localhost:5432/authdb")
    if err != nil {
        return nil, err
    }
    return conn, nil
}

func main() {
    // Redis client setup (optional, can be removed if not used)
    redisClient := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
    })
    defer redisClient.Close()

    // Router setup
    router := mux.NewRouter()
    router.HandleFunc("/register", RegisterHandler).Methods("POST")
    router.HandleFunc("/login", LoginHandler).Methods("POST")

    // Enable CORS
    c := cors.New(cors.Options{
        AllowedOrigins:   []string{"http://localhost:3000"},
        AllowCredentials: true,
        AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
        AllowedHeaders:   []string{"Content-Type", "Authorization"},
    })
    handler := c.Handler(router)

    // Start the server
    log.Println("Starting server on port 8080...")
    log.Fatal(http.ListenAndServe(":8080", handler))
}

// Password hashing function
func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

// Password comparison function
func checkPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

// Struct for user registration request
type RegisterRequest struct {
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"password"`
    Address  string `json:"address"`
    State    string `json:"state"`
    City     string `json:"city"`
}

// RegisterHandler - Handles the user registration
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
    var req RegisterRequest

    // Parse the JSON request body
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    // Check if required fields are provided
    if req.Username == "" || req.Email == "" || req.Password == "" {
        http.Error(w, "Missing required fields", http.StatusBadRequest)
        return
    }

    // Hash the password
    hashedPassword, err := hashPassword(req.Password)
    if err != nil {
        http.Error(w, "Error hashing password", http.StatusInternalServerError)
        return
    }

    // Save the user in the database
    conn, err := connectDB()
    if err != nil {
        log.Printf("Error connecting to the database: %v", err)
        http.Error(w, "Database connection error", http.StatusInternalServerError)
        return
    }
    defer conn.Close(ctx)

    _, err = conn.Exec(ctx, "INSERT INTO users (username, email, password, address, state, city) VALUES ($1, $2, $3, $4, $5, $6)",
        req.Username, req.Email, hashedPassword, req.Address, req.State, req.City)
    if err != nil {
        log.Printf("Error saving user to the database: %v", err)
        http.Error(w, "Error saving user to the database", http.StatusInternalServerError)
        return
    }

    // Return success response
    fmt.Fprintln(w, "Registration successful")
}

// Struct for login request
type User struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

// LoginHandler - Handles user login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    var user User

    // Parse the JSON request body
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    // Check the database for the user
    conn, err := connectDB()
    if err != nil {
        http.Error(w, "Unable to connect to database", http.StatusInternalServerError)
        return
    }
    defer conn.Close(ctx)

    var hashedPassword string
    err = conn.QueryRow(ctx, "SELECT password FROM users WHERE email=$1", user.Email).Scan(&hashedPassword)
    if err != nil {
        http.Error(w, "User not found", http.StatusUnauthorized)
        return
    }

    // Check the password hash
    if !checkPasswordHash(user.Password, hashedPassword) {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Return success response
    fmt.Fprintln(w, "Login successful")
}
