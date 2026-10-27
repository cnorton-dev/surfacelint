package report

import (
	"encoding/json"
	"github.com/cnorton-dev/surfacelint/internal/model"
	"io"
)

// PrintJSON writes machine-readable results without extra terminal markup.
func PrintJSON(w io.Writer, result model.Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
