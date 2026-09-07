package portal

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "golang.org/x/image/webp"
	"image"
	"image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func decodeArtwork(data []byte) (image.Image, error) {
	if len(data) > 8<<20 {
		return nil, errors.New("Artwork must be under 8 MiB.")
	}
	cfg, format, e := image.DecodeConfig(bytes.NewReader(data))
	if e != nil || !includes([]string{"jpeg", "png", "webp"}, format) {
		return nil, errors.New("Upload a decoded JPEG, PNG, or WebP image; SVG and other files are not supported.")
	}
	if cfg.Width < 1 || cfg.Height < 1 || int64(cfg.Width)*int64(cfg.Height) > 20000000 {
		return nil, errors.New("Image dimensions exceed 20 megapixels.")
	}
	im, _, e := image.Decode(bytes.NewReader(data))
	return im, e
}
func (a *App) upload(w http.ResponseWriter, r *http.Request, u *User, serviceID int) {
	if e := r.ParseMultipartForm(9 << 20); e != nil {
		a.fail(w, r, 400, "Invalid artwork upload (maximum 8 MiB).")
		return
	}
	defer r.MultipartForm.RemoveAll()
	f, _, e := r.FormFile("artwork_file")
	if e != nil {
		a.fail(w, r, 400, "Choose an image to upload.")
		return
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if e != nil {
		a.fail(w, r, 400, "Could not read image")
		return
	}
	im, e := decodeArtwork(b)
	if e != nil {
		a.fail(w, r, 400, e.Error())
		return
	}
	v := a.Store.service(serviceID)
	if serviceID != 0 && v == nil {
		a.fail(w, r, 404, "Save the service before uploading artwork.")
		return
	}
	id := secret()
	filename := id + ".jpg"
	path := filepath.Join(a.Config.DataDir, "uploads", filename)
	out, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		a.fail(w, r, 500, "Could not store artwork.")
		return
	}
	e = jpeg.Encode(out, im, &jpeg.Options{Quality: 90})
	closeErr := out.Close()
	if e == nil {
		e = closeErr
	}
	if e == nil {
		e = a.Store.Write(func(tx *sql.Tx) error {
			if _, e := tx.Exec("INSERT INTO media(id,service_id,filename,created) VALUES(?,?,?,?)", id, nullable(serviceID), filename, now()); e != nil {
				return e
			}
			if serviceID != 0 {
				v.Config.Artwork = "/media/" + id
				config, _ := json.Marshal(v.Config)
				if _, e := tx.Exec("UPDATE services SET config=? WHERE id=?", string(config), serviceID); e != nil {
					return e
				}
			} else {
				if _, e := tx.Exec("UPDATE settings SET logo=? WHERE id=1", "/media/"+id); e != nil {
					return e
				}
			}
			return audit(tx, u.ID, "upload artwork", idTarget("service", serviceID))
		})
	}
	if e != nil {
		os.Remove(path)
		a.fail(w, r, 500, "Could not save artwork.")
		return
	}
	dest := "/admin/settings"
	if serviceID != 0 {
		dest = fmt.Sprintf("/admin/services/%d", serviceID)
	}
	http.Redirect(w, r, dest+"?success=Artwork+uploaded", 303)
}
func (a *App) media(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var sid sql.NullInt64
	var filename string
	e := a.Store.DB.QueryRow("SELECT service_id,filename FROM media WHERE id=?", id).Scan(&sid, &filename)
	if e != nil {
		http.NotFound(w, r)
		return
	}
	if sid.Valid {
		v := a.Store.service(int(sid.Int64))
		if !a.Store.discover(a.current(r), v) {
			http.NotFound(w, r)
			return
		}
	} else if a.Store.Settings().Logo != "/media/"+id {
		http.NotFound(w, r)
		return
	}
	if filepath.Base(filename) != filename || strings.Contains(filename, "..") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	http.ServeFile(w, r, filepath.Join(a.Config.DataDir, "uploads", filename))
}
