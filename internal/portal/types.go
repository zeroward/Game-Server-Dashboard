package portal

import "html/template"

type User struct {
	PreviewService        int
	ID                    int
	Username, Email, Role string
	Enabled               bool
	Generation            int
}
type Category struct {
	ID                      int
	Name, Audience          string
	AccessService, Position int
}
type Field struct {
	Key, Label, Type string
	Required         bool
	Options          []string
}
type Value struct{ Label, Value string }
type ServiceConfig struct {
	Type        string  `json:"type"`
	Game        string  `json:"game"`
	Summary     string  `json:"summary"`
	Description string  `json:"description"`
	Tags        string  `json:"tags"`
	Artwork     string  `json:"artwork"`
	FocalX      int     `json:"focal_x"`
	FocalY      int     `json:"focal_y"`
	Host        string  `json:"host"`
	Port        string  `json:"port"`
	Version     string  `json:"version"`
	Platform    string  `json:"platform"`
	Connection  string  `json:"connection"`
	Custom      []Value `json:"custom"`
	Guide       string  `json:"guide"`
	Status      string  `json:"status"`
	StatusAt    string  `json:"status_at"`
	DirectLink  int     `json:"direct_link"`
	Fields      []Field `json:"fields"`
	Duration    bool    `json:"duration"`
}
type Service struct {
	Supportable               bool
	Recommended               bool
	Requestable               bool
	ID                        int
	Slug, Name                string
	CategoryID                int
	Published, Archived       bool
	Audience, DetailsAudience string
	AccessService             int
	Mode                      string
	Position                  int
	Featured                  bool
	Config                    ServiceConfig
	Details                   bool
	Links                     []Link
	HTML, GuideHTML           template.HTML
}
type Link struct {
	ID                      int
	Label, URL, Placement   string
	ParentID, AccessService int
	Audience                string
	Position                int
	Enabled                 bool
	Style                   string
	NewTab                  bool
	Icon, Description       string
}
type Announcement struct {
	ID                     int
	Title, Body, Placement string
	ParentID               int
	Audience               string
	AccessService          int
	Starts, Ends           string
	Enabled                bool
	HTML                   template.HTML
}
type Request struct {
	ID, UserID, ServiceID                      int
	ServiceName, Username, Kind, State, Reason string
	Fields                                     []Value
	RequestedEnd, Created, Updated             string
	Version                                    int
}
type Message struct {
	ID                   int
	Actor, Body, Created string
}
type Transition struct{ Actor, From, To, Created string }
type Access struct {
	ID, UserID, ServiceID                                     int
	Username, ServiceName, State, Granted, Expires, NextSteps string
	Version                                                   int
	Service                                                   *Service
}
type Notification struct {
	ID, RequestID, AccessID, DeviceID int
	Text, Created                     string
	Read                              bool
}
type Settings struct {
	Name, Description, Accent string
	Public                    bool
	Logo                      string
}
type Page struct {
	Security                              *SecurityPage
	Mail                                  *MailPage
	VPNEnabled                            bool
	VPN                                   *VPNPage
	Title, View, Error, Success, TokenURL string
	User                                  *User
	CSRF                                  template.HTML
	Settings                              Settings
	Categories                            []Category
	Services                              []Service
	Service                               *Service
	Links                                 []Link
	GlobalLinks                           []Link
	Announcements                         []Announcement
	Requests                              []Request
	Request                               *Request
	Messages, Notes                       []Message
	History                               []Transition
	Accesses                              []Access
	Notifications                         []Notification
	Unread                                int
	Users                                 []User
	EditUser                              *User
	Category                              *Category
	Link                                  *Link
	Announcement                          *Announcement
	Query, Filter, Tag                    string
	Actions                               []string
	AdminTab                              string
	Rows                                  [][]string
	Preview                               string
}
