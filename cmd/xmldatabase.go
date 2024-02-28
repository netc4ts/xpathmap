package main

import (
  "strings"
  "fmt"
  "os"
  "log"
  "net/http"
  "html/template"

  "github.com/antchfx/xmlquery"
)

const baseHtml = `
<html>
<head>
  <title>Anonymous Messaging</title>
</head>
<body>
  <form method="POST">
    <input name="username" placeholder="Username...">
    <br>
    <input name="message" placeholder="Message...">
    <br>
    <button type="submit">Submit</button>
  </form>
    <p>{{.}}</p>
</body>
</html>
`

type MessageDto struct {
  Username string `json:"username"`
  Message  string `json:"message"`
}

func checkAndExit(err error) {
  if err != nil {
    log.Panic(err)
    os.Exit(1)
  }
}

func main() {
  // === setting up XML database ===
  fmt.Println("Reading XML Database :)")
  dat, err := os.ReadFile("./database.xml")
  checkAndExit(err)

  xmlDatabase := string(dat)
  doc, err := xmlquery.Parse(strings.NewReader(xmlDatabase))
  checkAndExit(err)

  // === vulnerable search function to be used by the web application ===
  userExists := func(username string) bool {
    user := xmlquery.FindOne(doc, "//accounts/user[username='"+username+"']")
    if user != nil {
      fmt.Println(user.InnerText())
      return true
    } else {
      fmt.Println("User not found")
      return false
    }
  }

  // === Parsing HTML files ===
  templBaseHtml, err := template.New("かっこいいなテンプレート").Parse(baseHtml)
  if err != nil {
    log.Println("Error parsing HTML")
    log.Panic(err)
  }

  // === setting up WEB server ===
  serveMux := http.NewServeMux()
  serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request){
    w.Header().Set("Content-Type", "text/html")
    switch r.Method {
    case "GET":
      templBaseHtml.Execute(w, nil)
    case "POST":
      err := r.ParseForm()
      if err != nil {
	w.Write([]byte(err.Error()))
      }

      messageDto := &MessageDto{
	Username: r.Form.Get("username"),
	Message: r.Form.Get("message"),
      }

      if userExists(messageDto.Username) {
	templBaseHtml.Execute(w, "Message sent!")
      } else {
	templBaseHtml.Execute(w, "This user does not exist")
      }
    }
  })

  println("Server is up at http://localhost:1337 :)")
  log.Panic(http.ListenAndServe(":1337", serveMux))
}

