# -*- coding: utf-8 -*-
# ofs_vanisher.py
# OFS (Out-of-scope) Vanisher (Written by AI)
#
# - Auto-exclude: On load, Add, Edit, and context-menu actions
# - Context menu: Ignore Host (ANY) / Ignore Full URL (path only) — no popups
# - Tab: view/add/edit/remove/exclude/save entries (edit supported)
# - Auto-exclude tries to add both http://host/ and https://host/ to Burp scope exclude
# - Marks future responses with:
#       Content-Type: text/css; charset=UTF-8
#   and header X-OFS-Vanisher: ignored
#   (so you can hide them via MIME-type filtering)
#
# IMPORTANT for not seeing NEW out-of-scope items in HTTP history:
#   Enable Proxy > Options > Proxy history logging > "Don't send items to Proxy history if out of scope"
#
# Limitations:
# - Cannot delete already-recorded Proxy history entries (Burp API does not support this).
# - You **must** enable the above Proxy option for Burp to stop logging new out-of-scope requests.
# If you have any additional things to add do create an issue at https://github.com/ahrixia/ofs-vanisher

from burp import IBurpExtender, IContextMenuFactory, ITab, IHttpListener
from javax.swing import (JPanel, JButton, JLabel, JTextField, JScrollPane, JList,
                         JOptionPane, DefaultListModel, BoxLayout, BorderFactory, JMenuItem)
from java.awt import BorderLayout, Dimension
from java.awt.event import ActionListener
from java.util import ArrayList
from java.net import URL
import traceback, re

SETTING_KEY = "OFSVanisher.force.ignorelist"

BANNER = """
[OFS Vanisher] Loaded.
IMPORTANT: To prevent NEW out-of-scope items from appearing in HTTP history, enable:
  Proxy > Options > Proxy history logging > "Don't send items to Proxy history if out of scope"
(Existing history rows cannot be removed by extensions.)
""".strip()


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IHttpListener):

    # ===== Burp bootstrap =====
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("OFS Vanisher")

        # ordered ignore list
        self.ignorelist = []
        try:
            data = self._callbacks.loadExtensionSetting(SETTING_KEY)
            if data:
                for line in data.splitlines():
                    v = line.strip()
                    if v:
                        self.ignorelist.append(v)
        except Exception:
            pass

        # UI
        try:
            self._init_ui()
            self._callbacks.addSuiteTab(self)
        except Exception as e:
            print("OFS Vanisher UI init error: %s" % e)
            print(traceback.format_exc())

        # register hooks
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerHttpListener(self)

        # Auto-exclude all saved entries right away so NEW requests won't log (with correct Burp option)
        try:
            self._auto_exclude_on_load()
        except Exception as e:
            print("OFS Vanisher: auto-exclude on load failed: %s" % e)
            try:
                print(traceback.format_exc())
            except:
                pass

        print(BANNER)

    # ===== UI =====
    def _init_ui(self):
        self._panel = JPanel(BorderLayout())
        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.setBorder(BorderFactory.createEmptyBorder(6,6,6,6))
        top.add(JLabel("OFS Vanisher: Add/Edit auto-excludes immediately."))
        top.add(JLabel("Responses for ignored hosts/URLs are marked as text/css + X-OFS-Vanisher header to allow filtering."))
        top.add(JLabel("Reminder: enable Proxy >  Options > Proxy history logging > 'Don't send items to Proxy history if out of scope'."))
        self._panel.add(top, BorderLayout.NORTH)

        self.listModel = DefaultListModel()
        for item in self.ignorelist:
            self.listModel.addElement(item)
        self.jlist = JList(self.listModel)
        self.jlist.setVisibleRowCount(12)
        scroll = JScrollPane(self.jlist)
        scroll.setPreferredSize(Dimension(700,260))
        self._panel.add(scroll, BorderLayout.CENTER)

        # controls
        bottom = JPanel()
        bottom.setLayout(BoxLayout(bottom, BoxLayout.Y_AXIS))

        row1 = JPanel()
        row1.setLayout(BoxLayout(row1, BoxLayout.X_AXIS))
        self.inputField = JTextField()
        self.inputField.setColumns(40)
        addBtn = JButton("Add", actionPerformed=self._add_from_field)
        editBtn = JButton("Edit Selected", actionPerformed=self._edit_selected)
        removeBtn = JButton("Remove Selected", actionPerformed=self._remove_selected)
        row1.add(self.inputField)
        row1.add(addBtn)
        row1.add(editBtn)
        row1.add(removeBtn)
        bottom.add(row1)

        row2 = JPanel()
        row2.setLayout(BoxLayout(row2, BoxLayout.X_AXIS))
        excludeBtn = JButton("Exclude Selected (add to Burp scope exclude)", actionPerformed=self._exclude_selected)
        saveBtn = JButton("Save", actionPerformed=self._persist_settings)
        clearBtn = JButton("Clear All", actionPerformed=self._clear_all)
        row2.add(excludeBtn)
        row2.add(saveBtn)
        row2.add(clearBtn)
        bottom.add(row2)

        self._panel.add(bottom, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "OFS Vanisher"

    def getUiComponent(self):
        return self._panel

    # ===== Helpers: exclusion logic (single place) =====
    def _exclude_entry(self, entry, added=None, failed=None):
        """
        Try to exclude a single ignorelist entry via Burp's excludeFromScope.
        - Hosts: exclude BOTH http://host/ and https://host/
        - URL-bases: exclude exact URL (no query)
        - Regex: not supported by excludeFromScope (report as info)
        """
        if added is None: added = []
        if failed is None: failed = []

        try:
            if not entry:
                return added, failed

            if entry.startswith("^"):
                failed.append("%s (regex cannot be excluded programmatically)" % entry)
                return added, failed

            if entry.lower().startswith("http://") or entry.lower().startswith("https://"):
                try:
                    url_obj = URL(entry)
                    self._callbacks.excludeFromScope(url_obj)
                    added.append(entry)
                except Exception as e:
                    failed.append("%s (%s)" % (entry, e))
            else:
                # host: exclude ANY (http+https)
                try:
                    self._callbacks.excludeFromScope(URL("http://%s/" % entry))
                    self._callbacks.excludeFromScope(URL("https://%s/" % entry))
                    added.append(entry + " (ANY)")
                except Exception as e:
                    failed.append("%s (%s)" % (entry, e))
        except Exception as e:
            failed.append("%s (%s)" % (entry, e))

        return added, failed

    def _auto_exclude_on_load(self):
        added, failed = [], []
        for entry in list(self.ignorelist):
            added, failed = self._exclude_entry(entry, added, failed)

        if added:
            print("[OFS Vanisher] Auto-excluded on load:")
            for a in added:
                print("  - %s" % a)
        if failed:
            print("[OFS Vanisher] Auto-exclude failed/info:")
            for f in failed:
                print("  - %s" % f)

    def _persist_now(self):
        try:
            data = "\n".join(self.ignorelist)
            self._callbacks.saveExtensionSetting(SETTING_KEY, data)
            return True, None
        except Exception as e:
            return False, e

    # ===== UI actions =====
    def _add_from_field(self, evt=None):
        s = self.inputField.getText().strip()
        if not s:
            JOptionPane.showMessageDialog(None, "Enter an entry (host, http(s) URL, or regex starting with ^)", "OFS Vanisher", JOptionPane.WARNING_MESSAGE)
            return
        if s in self.ignorelist:
            JOptionPane.showMessageDialog(None, "Entry already exists.", "OFS Vanisher", JOptionPane.INFORMATION_MESSAGE)
            return

        self.ignorelist.append(s)
        self.listModel.addElement(s)
        self.inputField.setText("")

        # Auto-exclude immediately
        added, failed = self._exclude_entry(s)
        ok, err = self._persist_now()
        if added:
            print("[OFS Vanisher] Added & excluded: %s" % ", ".join(added))
        if failed:
            print("[OFS Vanisher] Add exclude info: %s" % ", ".join(failed))
        if not ok:
            print("Save failed: %s" % err)

    def _edit_selected(self, evt=None):
        idx = self.jlist.getSelectedIndex()
        if idx < 0:
            JOptionPane.showMessageDialog(None, "No item selected to edit.", "OFS Vanisher", JOptionPane.WARNING_MESSAGE)
            return
        orig = self.listModel.getElementAt(idx)
        newval = JOptionPane.showInputDialog(None, "Edit entry:", orig)
        if newval is None:
            return
        newval = newval.strip()
        if not newval:
            JOptionPane.showMessageDialog(None, "Entry cannot be empty.", "OFS Vanisher", JOptionPane.WARNING_MESSAGE)
            return
        if newval == orig:
            return

        self.listModel.set(idx, newval)
        try:
            self.ignorelist[idx] = newval
        except:
            self.ignorelist = [self.listModel.getElementAt(i) for i in range(self.listModel.getSize())]

        # Auto-exclude the new value
        added, failed = self._exclude_entry(newval)
        ok, err = self._persist_now()
        if added:
            print("[OFS Vanisher] Edited & excluded: %s" % ", ".join(added))
        if failed:
            print("[OFS Vanisher] Edit exclude info: %s" % ", ".join(failed))
        if not ok:
            print("Save failed: %s" % err)

    def _remove_selected(self, evt=None):
        sels = self.jlist.getSelectedIndices()
        if not sels:
            JOptionPane.showMessageDialog(None, "No items selected to remove.", "OFS Vanisher", JOptionPane.WARNING_MESSAGE)
            return
        for i in reversed(sels):
            val = self.listModel.getElementAt(i)
            self.listModel.remove(i)
            try:
                del self.ignorelist[i]
            except:
                try:
                    self.ignorelist.remove(val)
                except:
                    pass
        ok, err = self._persist_now()
        if not ok:
            JOptionPane.showMessageDialog(None, "Save failed: %s" % err, "OFS Vanisher", JOptionPane.ERROR_MESSAGE)

    def _exclude_selected(self, evt=None):
        sels = self.jlist.getSelectedIndices()
        if not sels:
            JOptionPane.showMessageDialog(None, "No items selected to exclude.", "OFS Vanisher", JOptionPane.WARNING_MESSAGE)
            return
        added, failed = [], []
        for i in sels:
            val = self.listModel.getElementAt(i)
            added, failed = self._exclude_entry(val, added, failed)

        try:
            self._callbacks.saveExtensionSetting(SETTING_KEY, "\n".join(self.ignorelist))
        except:
            pass

        if added:
            print("[OFS Vanisher] Excluded from scope (via API):")
            for a in added:
                print("  - %s" % a)
        if failed:
            print("[OFS Vanisher] Failed / info for excludeFromScope:")
            for f in failed:
                print("  - %s" % f)

        msg = ""
        if added:
            msg += "Excluded from scope:\n" + "\n".join(added) + "\n\n"
        if failed:
            msg += "Failed / info:\n" + "\n".join(failed)
        if not msg:
            msg = "No changes made."
        JOptionPane.showMessageDialog(None, msg, "OFS Vanisher", JOptionPane.INFORMATION_MESSAGE)

    def _persist_settings(self, evt=None):
        ok, err = self._persist_now()
        if ok:
            JOptionPane.showMessageDialog(None, "Saved.", "OFS Vanisher", JOptionPane.INFORMATION_MESSAGE)
        else:
            JOptionPane.showMessageDialog(None, "Save failed: %s" % err, "OFS Vanisher", JOptionPane.ERROR_MESSAGE)

    def _clear_all(self, evt=None):
        confirm = JOptionPane.showConfirmDialog(None, "Clear all OFS Vanisher entries?", "Confirm", JOptionPane.YES_NO_OPTION)
        if confirm != JOptionPane.YES_OPTION:
            return
        self.listModel.clear()
        self.ignorelist = []
        try:
            self._callbacks.saveExtensionSetting(SETTING_KEY, "")
        except:
            pass
        print("[OFS Vanisher] Cleared all entries. (Scope excludes remain in Burp's configuration.)")

    # ===== Context menu (two direct actions) =====
    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        host_item = JMenuItem("OFS Vanisher: Ignore Host (ANY)")
        host_item.addActionListener(self.HostAction(self, invocation))
        menu_list.add(host_item)
        url_item = JMenuItem("OFS Vanisher: Ignore Full URL (path only)")
        url_item.addActionListener(self.URLAction(self, invocation))
        menu_list.add(url_item)
        return menu_list

    class HostAction(ActionListener):
        def __init__(self, outer, invocation):
            self.outer = outer
            self.invocation = invocation

        def actionPerformed(self, event):
            try:
                msgs = self.invocation.getSelectedMessages()
                if not msgs:
                    return
                added_entries = []
                for m in msgs:
                    try:
                        svc = m.getHttpService()
                        host = svc.getHost()
                    except:
                        host = None
                    if not host:
                        try:
                            req = m.getRequest()
                            info = self.outer._helpers.analyzeRequest(req)
                            host = info.getUrl().getHost()
                        except:
                            host = None
                    if not host:
                        continue
                    if host not in self.outer.ignorelist:
                        self.outer.ignorelist.append(host)
                        self.outer.listModel.addElement(host)
                        added_entries.append(host)
                    # Exclude immediately (even if it already existed)
                    self.outer._exclude_entry(host)

                if added_entries:
                    try:
                        self.outer._callbacks.saveExtensionSetting(SETTING_KEY, "\n".join(self.outer.ignorelist))
                    except:
                        pass
                    print("[OFS Vanisher] Added host(s): %s" % ", ".join(added_entries))
            except Exception as e:
                print("HostAction error: %s" % e)
                try:
                    print(traceback.format_exc())
                except:
                    pass

    class URLAction(ActionListener):
        def __init__(self, outer, invocation):
            self.outer = outer
            self.invocation = invocation

        def actionPerformed(self, event):
            try:
                msgs = self.invocation.getSelectedMessages()
                if not msgs:
                    return
                added_entries = []
                for m in msgs:
                    try:
                        req = m.getRequest()
                        info = self.outer._helpers.analyzeRequest(req)
                        u = info.getUrl()
                        if not u:
                            continue
                        try:
                            u_base = URL(u.getProtocol(), u.getHost(), u.getPort(), u.getPath()).toString()
                        except Exception:
                            full = u.toString()
                            u_base = full.split('?', 1)[0]
                        if u_base not in self.outer.ignorelist:
                            self.outer.ignorelist.append(u_base)
                            self.outer.listModel.addElement(u_base)
                            added_entries.append(u_base)
                        # Exclude immediately (even if it already existed)
                        self.outer._exclude_entry(u_base)
                    except Exception:
                        try:
                            print(traceback.format_exc())
                        except:
                            pass
                if added_entries:
                    try:
                        self.outer._callbacks.saveExtensionSetting(SETTING_KEY, "\n".join(self.outer.ignorelist))
                    except:
                        pass
                    print("[OFS Vanisher] Added URL-base(s): %s" % ", ".join(added_entries))
            except Exception as e:
                print("URLAction error: %s" % e)
                try:
                    print(traceback.format_exc())
                except:
                    pass

    # ===== Matching and response marking =====
    def _matches_ignore(self, host, url_base):
        try:
            for entry in self.ignorelist:
                if not entry:
                    continue
                if entry.startswith("^"):
                    try:
                        if re.search(entry, host) or re.search(entry, url_base):
                            return True
                    except re.error:
                        continue
                elif entry.lower().startswith("http://") or entry.lower().startswith("https://"):
                    if url_base == entry:
                        return True
                else:
                    if host == entry or (host and host.endswith("." + entry)):
                        return True
        except Exception:
            try:
                print(traceback.format_exc())
            except:
                pass
        return False

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only responses
        if messageIsRequest:
            return
        try:
            svc = messageInfo.getHttpService()
            host = svc.getHost() if svc else None
            url_base = None
            try:
                req = messageInfo.getRequest()
                info = self._helpers.analyzeRequest(req)
                u = info.getUrl() if info else None
                if u:
                    try:
                        url_base = URL(u.getProtocol(), u.getHost(), u.getPort(), u.getPath()).toString()
                    except:
                        url_base = u.toString().split('?', 1)[0]
            except:
                url_base = None

            if not host:
                return

            if not self._matches_ignore(host, url_base if url_base else ""):
                return

            # matched: mark response as CSS and add marker header so it's easy to filter/hide
            response = messageInfo.getResponse()
            if not response:
                return
            respInfo = self._helpers.analyzeResponse(response)
            headers = list(respInfo.getHeaders())
            # Remove any existing Content-Type header first
            headers = [h for h in headers if not h.lower().startswith("content-type:")]
            headers.append("Content-Type: text/css; charset=UTF-8")
            headers.append("X-OFS-Vanisher: ignored")
            body = response[respInfo.getBodyOffset():]
            newresp = self._helpers.buildHttpMessage(headers, body)
            messageInfo.setResponse(newresp)

        except Exception as e:
            try:
                print("OFS Vanisher process error: %s" % e)
                print(traceback.format_exc())
            except:
                pass
