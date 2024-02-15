package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"strings"

	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var SECRET_KEY = []byte("gosecretkey")

type User struct {
	FirstName string `json:"firstname" bson:"firstname"`
	LastName  string `json:"lastname" bson:"lastname"`
	Email     string `json:"email" bson:"email"`
	Password  string `json:"password" bson:"password"`
}

var client *mongo.Client

func getHash(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

func GenerateJWT(user User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"firstname": user.FirstName,
			"lastname":  user.LastName,
			"email":     user.Email,
		})
	tokenString, err := token.SignedString(SECRET_KEY)
	if err != nil {
		log.Println("Error in JWT token generation")
		return "", err
	}
	return tokenString, nil
}

func userSignup(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	var user User
	var dbUser User
	json.NewDecoder(request.Body).Decode(&user)
	collection := client.Database("GODB").Collection("user")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&dbUser)

	if err == nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{"message":"This email already exists"}`))
		return
	}
	user.Password = getHash([]byte(user.Password))
	_, err1 := collection.InsertOne(ctx, user)
	if err1 != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{"message":"Failed to create user"}`))
		return
	}
	// json.NewEncoder(response).Encode(result)
	jwtToken, err := GenerateJWT(user)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}
	// response.Write([]byte(`{"token":"` + jwtToken + `"}`))
	response.Header().Set("Authorization", "Bearer "+jwtToken)
}

func userLogin(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	var user User
	var dbUser User
	json.NewDecoder(request.Body).Decode(&user)
	collection := client.Database("GODB").Collection("user")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&dbUser)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{"message":"Sign Up"}`))
		return
	}
	userPass := []byte(user.Password)
	dbPass := []byte(dbUser.Password)

	passErr := bcrypt.CompareHashAndPassword(dbPass, userPass)

	if passErr != nil {
		log.Println(passErr)
		response.Write([]byte(`{"response":"Wrong Password!"}`))
		return
	}
	jwtToken, err := GenerateJWT(user)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}
	// response.WriteHeader(http.StatusOK)
	// response.Write([]byte(`{"token":"` + jwtToken + `"}`))
	response.Header().Set("Authorization", "Bearer "+jwtToken)

}

func uploadImage(response http.ResponseWriter, request *http.Request) {
	// Extract JWT token from Authorization header
	tokenString := request.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(response, "Authorization token required", http.StatusUnauthorized)
		return
	}

	// Extract JWT token
	parts := strings.Split(tokenString, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(response, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}
	tokenString = parts[1]

	// Parse JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check token signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			http.Error(response, "unexpected signing method", http.StatusUnauthorized)
		}
		return SECRET_KEY, nil
	})
	if err != nil || !token.Valid {
		http.Error(response, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Token is valid, proceed to image upload
	// Handle image upload logic here

	// Get the uploaded file
	file, handler, err := request.FormFile("image")
	if err != nil {
		http.Error(response, "Error uploading image", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Read the file content
	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(response, "Error reading image", http.StatusInternalServerError)
		return
	}

	// Store the image data in MongoDB
	collection := client.Database("GODB").Collection("images")
	_, err = collection.InsertOne(context.TODO(), bson.M{
		"filename": handler.Filename,
		"data":     fileBytes,
	})
	if err != nil {
		http.Error(response, "Error storing image in MongoDB", http.StatusInternalServerError)
		return
	}

	// Send a success response
	response.WriteHeader(http.StatusOK)
	response.Write([]byte("Image uploaded successfully"))

}

func main() {
	log.Println("Starting the application")

	router := mux.NewRouter()
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	// Create a new client and connect to the server
	client, _ = mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb+srv://naman2130:<password>@cluster0.wxiinke.mongodb.net/?retryWrites=true&w=majority").SetServerAPIOptions(serverAPI))

	router.HandleFunc("/api/user/login", userLogin).Methods("POST")
	router.HandleFunc("/api/user/signup", userSignup).Methods("POST")
	router.HandleFunc("/homepage/upload", uploadImage).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))

}
