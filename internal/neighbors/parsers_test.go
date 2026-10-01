package neighbors

import "testing"

func TestParseLinuxIPNeigh(t *testing.T) {
	text := "192.168.1.50 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n" +
		"192.168.1.51 dev eth0  FAILED\n" +
		"192.168.1.52 dev wlan0 lladdr 11:22:33:44:55:66 STALE\n"
	rows := parseLinuxIPNeigh(text)
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].IP != "192.168.1.50" || rows[0].MAC != "aa:bb:cc:dd:ee:ff" || rows[0].Iface != "eth0" {
		t.Errorf("rows[0] = %+v", rows[0])
	}
	if rows[1].IP != "192.168.1.52" || rows[1].MAC != "11:22:33:44:55:66" {
		t.Errorf("rows[1] = %+v", rows[1])
	}
}

func TestParseProcNetARP(t *testing.T) {
	text := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.1.50      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n" +
		"192.168.1.51      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
	rows := parseProcNetARP(text)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1 (incomplete all-zero MAC skipped)", len(rows))
	}
	if rows[0].IP != "192.168.1.50" || rows[0].MAC != "aa:bb:cc:dd:ee:ff" || rows[0].Iface != "eth0" {
		t.Errorf("rows[0] = %+v", rows[0])
	}
}

func TestParseWindowsARP(t *testing.T) {
	text := "Interface: 192.168.1.5 --- 0x5\n" +
		"  Internet Address      Physical Address      Type\n" +
		"  192.168.1.50          aa-bb-cc-dd-ee-ff     dynamic\n" +
		"  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
	rows := parseWindowsARP(text)
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].IP != "192.168.1.50" || rows[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("rows[0] = %+v", rows[0])
	}
}

func TestParseWindowsNetsh(t *testing.T) {
	text := "Interface 12: Wi-Fi\n\n" +
		"Internet Address                              Physical Address   Type\n" +
		"fe80::1                                        aa-bb-cc-dd-ee-ff Reachable (Router)\n"
	rows := parseWindowsNetsh(text)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if rows[0].IP != "fe80::1" || rows[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("rows[0] = %+v", rows[0])
	}
}

func TestParseBSDARP(t *testing.T) {
	text := "? (192.168.1.50) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n" +
		"? (192.168.1.51) at (incomplete) on en0 ifscope [ethernet]\n"
	rows := parseBSDARP(text)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if rows[0].IP != "192.168.1.50" || rows[0].MAC != "aa:bb:cc:dd:ee:ff" || rows[0].Iface != "en0" {
		t.Errorf("rows[0] = %+v", rows[0])
	}
}

func TestParseBSDNDP(t *testing.T) {
	text := "Neighbor                             Linklayer Address  Netif Expire    S Flags\n" +
		"fe80::1%en0                           aa:bb:cc:dd:ee:02  en0   23s       R\n"
	rows := parseBSDNDP(text)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if rows[0].MAC != "aa:bb:cc:dd:ee:02" || rows[0].Iface != "en0" {
		t.Errorf("rows[0] = %+v", rows[0])
	}
}

func TestIsUnicast(t *testing.T) {
	cases := []struct {
		mac  string
		want bool
	}{
		{"aa:bb:cc:dd:ee:ff", true},
		{"ff:ff:ff:ff:ff:ff", false}, // broadcast
		{"01:00:5e:00:00:01", false}, // multicast
		{"33:33:00:00:00:01", false}, // IPv6 multicast
		{"02:42:ac:11:00:02", true},  // locally administered unicast (Docker)
	}
	for _, c := range cases {
		if got := isUnicast(c.mac); got != c.want {
			t.Errorf("isUnicast(%q) = %v, want %v", c.mac, got, c.want)
		}
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := map[string]string{
		"192.168.1.5":        "192.168.1.5",
		"::FFFF:192.168.1.5": "192.168.1.5",
		"FE80::1%eth0":       "fe80::1",
	}
	for in, want := range cases {
		if got := normalizeIP(in); got != want {
			t.Errorf("normalizeIP(%q) = %q, want %q", in, got, want)
		}
	}
}
