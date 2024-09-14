{.define: ssl.}

import std/[os, httpclient, parsecsv, strutils, streams, json, times, base64]


const
  virusTotalKey{.strdefine.}: string = ""
  json_dir = "json/"


if not dirExists("json"):
  createDir("json")

var
  client = newHttpClient("Nim-Lang False Positive Reduction Efforts <3")
  hashes: seq[string] = @[]
  versions: seq[string] = @[]

var p: CsvParser
p.open("vt_links")
while p.readRow():
  let hashArray = p.row[1].split("/")
  hashes.add(hashArray[high(hashArray)])
  versions.add(p.row[0])
p.close()

let stable = client.getContent("https://nim-lang.org/channels/stable").strip()

proc findLatestVersion(): string = 
  # I hate this hacky code as well...
  type ParsingLevel = enum
    LMajor, LMinor, LPatch

  var
    true_ver: seq[(int, int, int)] = @[]
    latest_ver: (int, int, int) = (0,0,0)
    
  
  for pre_version in versions:
    let version = pre_version[0..^5]
    var
      major, minor, patch = ""
      level = LMajor
    for ch in version:
      case ch:
      of '.':
        case level:
        of LMajor: level = LMinor
        of LMinor: level = LPatch
        of LPatch: break
      else:
        case level:
        of LMajor: major.add(ch)
        of LMinor: minor.add(ch)
        of LPatch: patch.add(ch)
    
    true_ver.add((
      parseInt(major),
      parseInt(minor),
      parseInt(patch)
    ))
  
  for ver in true_ver:
    # I hate this code 
    # Here follows a okay-ish messy explanation

    if ver[0] < latest_ver[0]:
      # If the major is lower than the currently saved one then leave.
      # This was important because 1.6.14 could somehow bypass 2.0.0 without this
      continue

    if ver[0] > latest_ver[0]:
      # If major is higher than what we have then save it.
      latest_ver = ver
      continue
    
    if ver[1] < latest_ver[1]:
      # If minor is lower than what we have then leave
      # Same reason as the major lower check.
      continue

    if ver[1] > latest_ver[1]:
      # If minor is higher than what we have then save
      latest_ver = ver
      continue

    if ver[2] < latest_ver[2]:
      # If patch is lower than what we have then leave
      continue

    if ver[2] > latest_ver[2]:
      # If patch is higher than what we have then save
      latest_ver = ver
  
  return $latest_ver[0] & '.' & $latest_ver[1] & '.' & $latest_ver[2]

proc atoi*(s: string): int =
  # parseInt crashes on non-Int values, so I made this hacky thing.
  # the Response[].status field is a string containing the code that we are interested in but also some text that we are not so interested in.
  # That text sadly crashes parseInt() (I thought parseInt would be more secure :eye_roll:)
  var tmp = ""
  for ch in s:
    case ch
    of '0': tmp.add(ch)
    of '1': tmp.add(ch)
    of '2': tmp.add(ch)
    of '3': tmp.add(ch)
    of '4': tmp.add(ch)
    of '5': tmp.add(ch)
    of '6': tmp.add(ch)
    of '7': tmp.add(ch)
    of '8': tmp.add(ch)
    of '9': tmp.add(ch)
    else: continue
  return parseInt(tmp)

# If this is not the latest then download the latest from nim's site and submit it to VirusTotal
echo "Stable version: \"", stable, "\""
if stable != findLatestVersion():
  # Download x32 and x64 nim releases and store them in memory for now.
  for sample in @[
    (stable & "_x32", client.getContent("https://nim-lang.org/download/nim-" & stable & "_x32.zip")),
    (stable & "_x64", client.getContent("https://nim-lang.org/download/nim-" & stable & "_x64.zip"))  
  ]:

    # First, generate a special link for uploads (future-proofing in case nim grows over 32mb)
    # Note from me five days into the future: VirusTotal reports 2.0.4 64bit as 32mb? So this was maybe a good idea anyway.
    echo "Generating upload link"
    client.headers = newHttpHeaders({
      "X-Apikey": virusTotalKey
    })

    let pre_url = client.getContent("https://www.virustotal.com/api/v3/files/upload_url")
    if pre_url.isEmptyOrWhitespace():
      echo "Failed to generate link."
      quit(1)
    let url = pre_url.parseJson()["data"].getStr()


    echo "Generating submission request (Aka. building custom body) for ", sample[0]
    client.headers = newHttpHeaders({
      "X-Apikey": virusTotalKey,
      "Content-Type": "multipart/form-data; boundary=---011000010111000001101001",
      "Accept": "application/json"
    })

    var data = newMultipartData()
    data["file"] = sample[1]

    # I tried using multipart but it simply wouldnt work...
    var custom_body = """
-----011000010111000001101001
Content-Disposition: form-data; name="file"; filename="$#.zip"
Content-Type: application/zip

data:application/zip;name=$#.zip;base64,$#
-----011000010111000001101001--
""" % [sample[0], sample[0], sample[1].encode()]

    echo "Submitting sample ", sample[0], ".zip"
    let response = client.request(
      url,
      body=custom_body,
      httpMethod = HttpPost,
    )

    if response[].status.atoi() == 200:
      echo "Request was successful, sleeping for a bit before fetching hash for ", sample[0]
      sleep(15000)
      var id = response[].bodyStream.readAll().parseJson()["data"]["id"].getStr()
      client.headers = newHttpHeaders({
        "x-apikey": virusTotalKey,
        "accept": "application/json"
      })
      echo "Fetching real hash for ", sample[0]
      echo "Analysis ID (Aka. \"fake\" id): ", id
      var fake_id = id # We have still got to save it for the next part.
      # So there is this bug where VirusTotal is way too slow to get the hash and that breaks everything
      while id == fake_id:
        try:
          id = client.getContent("https://www.virustotal.com/api/v3/analyses/" & id).parseJson()["meta"]["file_info"]["sha256"].getStr()
        except:
          echo "Request failed, trying again after 15 seconds"
          sleep(15000)
      echo "Fetched real hash, it's ", id
      let vt_links_file = readFile("vt_links")
      echo "Saving everything to vt_links file!!!!"
      writeFile("vt_links", "$#,https://www.virustotal.com/gui/file/$#\n$#" % [sample[0], id, vt_links_file])
    else:
      echo "!!! Request was not successful! Sample: ", sample[0]
      echo response[].status
      echo response[].bodyStream.readAll()
      quit(1)
#if stable != findLatestVersion(): 


# Rescan every previous hash
proc rescanHash(hash: string): string =
  let resp = client.request("https://www.virustotal.com/api/v3/files/" & hash & "/analyse", HttpPost, "", newHttpHeaders({ "x-apikey": virusTotalKey }))[].bodyStream.readAll()
  try:
    return resp.parseJson()["data"]["id"].getStr()
  except:
    echo "Couldn't scan hash, response: ", resp
    quit(1)

proc isDoneScanning(id: string, jason: var string): bool =
  try:
    let resp = client.request("https://www.virustotal.com/api/v3/analyses/" & id, HttpGet, "", newHttpHeaders({ "x-apikey": virusTotalKey }))[].bodyStream.readAll()
    if resp.parseJson()["data"]["attributes"]["status"].getStr().toLowerAscii() == "completed":
      jason = resp
      return true
    else:
      return false
  except CatchableError as err:
    echo "Exception encountered? ", err.msg
    return false

# This next bit of code decides what the folder should be named.
# Retrieve current UTC time and format it as # 2024-04-27-10:38:00
# Note: This date marks the beginning of the scan, the hash files weren't downloaded yet! downloadJson() hasn't been called up to this point!
let now = now().utc().format(initTimeFormat("yyyy-MM-dd-hh:mm:ss")) 
var dir_to_create = json_dir & "json-" & now

var i = 0
while dirExists(dir_to_create):
  inc(i)
  if not dirExists(dir_to_create & "-" & $i):
    dir_to_create = dir_to_create & "-" & $i
    break
writeFile("latest",dir_to_create) # Save folder name to a file named "latest" so that people can easily see the latest data.
createDir(dir_to_create) # Finally, create directory

i = -1
# Loop over every hash, request a re-scan, wait for the re-scan to finish
# and then save it as a file to the "dir_to_create" location.
# Also, the name of the file will be the version itself, just so we wont have to look at hashes.
for hash in hashes:
  inc(i)
  echo "Re-scanning hash: ", hash
  echo "Which belongs to version: ", versions[i]
  let id = rescanHash(hash)

  var count = 0
  var jason: string # Store json string here so we dont make an extra API call
  # Check if hash is done scanning
  while isDoneScanning(id, jason) == false:
    inc count
    echo "Scanned ", count, " times"
    sleep(90000) # Sleep for a minute and a half and then check again
  
  writeFile(
    dir_to_create & "/" & versions[i] & ".json", # Filename
    jason
  )