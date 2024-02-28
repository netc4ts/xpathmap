package util

import "net/url"

func MapDeepCopy(dst url.Values, src url.Values) {
  for k,v := range src {
    dst[k] = v
  }
}
