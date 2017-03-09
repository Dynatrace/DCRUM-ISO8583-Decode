--[[
Copyright © 2017 Dynatrace LLC. 
All rights reserved. 
Unpublished rights reserved under the Copyright Laws of the United States.

U.S. GOVERNMENT RIGHTS-Use, duplication, or disclosure by the U.S. Government is
subject to restrictions as set forth in Dynatrace LLC license agreement and as
provided in DFARS 227.7202-1(a) and 227.7202-3(a) (1995), DFARS
252.227-7013(c)(1)(ii) (OCT 1988), FAR 12.212 (a) (1995), FAR 52.227-19, 
or FAR 52.227-14 (ALT III), as applicable.

This product contains confidential information and trade secrets of Dynatrace LLC. 
Disclosure is prohibited without the prior express written permission of Dynatrace LLC. 
Use of this product is subject to the terms and conditions of the user's License Agreement with Dynatrace LLC.
See the license agreement text online at https://community.dynatrace.com/community/download/attachments/5144912/dynaTraceES.txt?version=3&modificationDate=1441261483927&api=v2
--]]
require 'amd'
require 'struct'
-- script name --
function script_name()
  return "ISO8583Parser"
end

local LogFlag = 0     --0 to turn logging off, 1 to turn it on
local taskParm = 4    --Parameter to use in order to set the CAS Task name for an operation
local MTIbeg = 3      --number of characters into the payload where the MTI code begins
local MTIend = 6      --number of characters into the payload where the MTI code ends
local errorAttrib = 0 --CAS OA 1 - error attribute
local warnAttrib = 1  --CAS OA 2 - warning attribute
local acceptAttrib = 2  --CAS OA 3 - accept card txn
local denyAttrib = 3    --CAS OA 4 - deny card txn
local denyRetainAttrib = 4  --CAS OA 5 - deny and retain card attrib
local functionCodeBit = 24    --bit used to determine if there is a funciton code
local actionCodeBit = 39      --bit used to determine if there is an action code
local usernameBit = 42        --bit used to determine if there is a username set
local stanBit = 11        -- bit used to determine if there is a System trace audit number (STAN)

local fixedPayloadBegin = 7
local fixedHexLength = 16          --length of the fixed payload in hex
local varPayloadBegin = fixedPayloadBegin + fixedHexLength          --should be immediatly after the fixedpayload length



-- MTIcodes look up table - reported in task parameter
local MTIcodes = {
  [1100] = "Authorization Request",
  [1101] = "Authorization Request Repeat",
  [1110] = "Authorization Request Response",
  [1120] = "Authorization Advice",
  [1121] = "Authorization Advice Repeat",
  [1130] = "Authorization Advice Response",
  [1140] = "Authorization Notification",
  [1200] = "Financial Transaction Request",
  [1201] = "Financial Transaction Request Repeat",
  [1210] = "Financial Transaction Request Response",
  [1220] = "Financial Transaction Advice",
  [1230] = "Financial Transaction Advice Response",
  [1240] = "Financial Transaction Notification",
  [1304] = "File Action Request",
  [1305] = "File Action Request Repeat",
  [1314] = "File Action Request Response",
  [1324] = "File Action Advice",
  [1325] = "File Action Advice Repeat",
  [1334] = "File Action Advice Response",
  [1420] = "Reversal Advice",
  [1421] = "Reversal Advice Repeat",
  [1430] = "Reversal Advice Response",
  [1440] = "Reversal Notification",
  [1644] = "Administrative Notification",
  [1804] = "Network Management Request",
  [1805] = "Network Management Request Repeat",
  [1814] = "Network Management Request Response"
  }

-- Function code look up table - Repored in Operation name  
local functionCodes = {
  [100] = "Original authorization - amount accurate", 
  [101] = "Original authorization - amount estimated", 
  [102] = "Replacement authorization - amount accurate",
  [103] = "Replacement authorization - amount estimated",
  [104] = "Resubmission - amount accurate",
  [105] = "Resubmission - amount estimated",
  [106] = "Supplementary authorization - amount accurate",
  [107] = "Supplementary authorization - amount estimated",
  [108] = "Inquiry",
  [172] = "Recurring Payment",
  [200] = "Original financial request/advice",
  [201] = "Previously approved authorization - amount same",
  [202] = "Previously approved authorization - amount differs",
  [203] = "Resubmission of a previously denied financial request",
  [204] = "Resubmission of a previously reversed financial transaction",
  [205] = "First representment",
  [206] = "Second representment",
  [207] = "Third or subsequent representment",
  [208] = "Representment reversal",
  [300] = "File unassigned",
  [301] = "Add record or add/update record (for AEGN Network Exception File updates)",
  [302] = "Change record",
  [303] = "Delete record",
  [304] = "Replace record (this is an add that switches to a change record if the record already exists on file)",
  [305] = "Inquire on the Card data source",
  [306] = "Replace file",
  [307] = "Add file",
  [308] = "Delete file",
  [309] = "Card administration",
  [400] = "Full reversal, transaction did not complete as approved",
  [401] = "Partial reversal, transaction did not complete for full amount",
  [450] = "First full chargeback",
  [451] = "Second full chargeback",
  [452] = "Third full chargeback",
  [453] = "First partial chargeback",
  [454] = "Second partial chargeback",
  [455] = "Third partial chargeback",
  [456] = "First full chargeback reversal",
  [457] = "Second full chargeback reversal",
  [459] = "First partial chargeback reversal",
  [460] = "Second partial chargeback reversal",
  [650] = "Unable to parse message",
  [801] = "System condition/sign-on",
  [802] = "System condition/sign-off",
  [809] = "System security/key request (outbound key)",
  [810] = "System security/key request (inbound key)",
  [811] = "System security/key change (both keys)",
  [817] = "System security/key change (outbound key)",
  [818] = "System security/key change (inbound key)",
  [819] = "System condition/sign on acquirer only processor",
  [820] = "System condition/sign on Issuer only processor",
  [821] = "System accounting/cutover (future)",
  [822] = "System accounting/checkpoint (future)",
  [823] = "System condition/sign off acquirer only processor",
  [824] = "System condition/sign off Issuer only processor",
  [831] = "System audit control/echo test"
  }
  
  
  --Action Code look up table - Report in  Operation Attribute (ADS equired to view vmessage)
local actionCodes = {
  [000] = "Approved", 
  [001] = "Honor with identification",
  [002] = "Approved for partial amount",
  [003] = "Approved (VIP)",
  [004] = "Approved, update Track 3",
  [005] = "Approved, account type specified by card issuer",
  [006] = "Approved for partial amount, account type specified by card issuer",
  [007] = "Approved, update ICC",
  [070] = "Customer-specific approval codes",
  [071] = "Customer-specific approval codes",
  [072] = "Customer-specific approval codes",
  [073] = "Customer-specific approval codes",
  [074] = "Customer-specific approval codes",
  [075] = "Customer-specific approval codes",
  [076] = "Customer-specific approval codes",
  [077] = "Customer-specific approval codes",
  [078] = "Customer-specific approval codes",
  [079] = "Customer-specific approval codes",
  [080] = "Approved, backup",
  [081] = "Approved, overdraft",
  [082] = "Approved, surcharge",
  [083] = "Approved, OAR",
  [084] = "Approved, no EMV script",
  [085] = "Approved, administration transaction, outside the balance cutover window",
  [086] = "Approved, administration transaction, anytime balance cutover window",
  [087] = "Purchase amount only, no cash back allowed",
  [100] = "Denied, do not honor",
  [101] = "Denied, expired card",
  [102] = "Denied, suspected fraud",
  [103] = "Denied, card acceptor contact acquirer",
  [104] = "Denied, restricted card",
  [105] = "Denied, card acceptor call acquirer’s security department",
  [106] = "Denied, allowable PIN tries exceeded",
  [107] = "Denied, refer to card issuer",
  [108] = "Denied, refer to card issuer’s special conditions",
  [109] = "Denied, invalid merchant",
  [110] = "Denied, invalid amount",
  [111] = "Denied, invalid card number",
  [112] = "Denied, PIN data required",
  [113] = "Denied, unacceptable fee",
  [114] = "Denied, no account of type requested",
  [115] = "Denied, requested function not supported",
  [116] = "Denied not sufficient funds",
  [117] = "Denied, incorrect PIN",
  [118] = "Denied, no card record",
  [119] = "Denied, transaction not permitted to cardholder",
  [120] = "Denied, transaction not permitted to terminal",
  [121] = "Denied, exceeds withdrawal amount limit",
  [122] = "Denied, security violation",
  [123] = "Denied, exceeds withdrawal frequency limit",
  [124] = "Denied, violation of law",
  [125] = "Denied, card not effective",
  [126] = "Denied, invalid PIN block",
  [127] = "Denied, PIN length error",
  [128] = "Denied, PIN key synchronization error",
  [129] = "Denied, suspected counterfeit card",
  [130] = "Deny, transaction over the limit",
  [146] = "Deny, CVV or CVC failure",
  [160] = "Hot Card",
  [161] = "Temporary Card Block",
  [162] = "Restricted Card Status",
  [163] = "Exceeded Txn Declines",
  [168] = "ARQC failed, decline, return card",
  [169] = "ARQC failed, refer",
  [170] = "CVR failed, decline, return card",
  [171] = "CVR failed, refer",
  [172] = "TVR failed, decline, return card",
  [173] = "TVR failed, refer",
  [174] = "ATC failed, decline, return card",
  [175] = "ATC failed, refer",
  [176] = "Denied, fallback check",
  [177] = "Referred, fallback check",
  [180] = "Denied, amount not found",
  [181] = "Denied, PIN change required",
  [182] = "Denied, new PIN invalid",
  [183] = "Denied, issuer/bank not found",
  [184] = "Denied, issuer/bank not effective",
  [185] = "Denied, customer/vendor not found",
  [186] = "Denied, customer/vendor not effective",
  [187] = "Denied, customer/vendor account invalid",
  [188] = "Denied, vendor not found",
  [189] = "Denied, vendor not effective",
  [190] = "Denied, vendor data invalid",
  [191] = "Denied, payment data invalid",
  [192] = "Denied, personal information not found",
  [193] = "Denied, scheduled transaction already exists",
  [194] = "Denied, user not allowed to perform the requested function",
  [195] = "Denied, print mini-statement instead",
  [196] = "Denied, no statement data available",
  [197] = "Deny, card activation declined",
  [200] = "Retain card, do not honor",
  [201] = "Retain card, expired card",
  [202] = "Retain card, suspected fraud",
  [203] = "Retain card, card acceptor contact acquirer",
  [204] = "Retain card, restricted card",
  [205] = "Retain card, card acceptor call acquirer’s security department",
  [206] = "Retain card, allowable PIN tries exceeded",
  [207] = "Retain card, special conditions",
  [208] = "Retain card, lost card",
  [209] = "Retain card, stolen card",
  [210] = "Retain card, suspected counterfeit card",
  [280] = "ARQC failed, decline, retain card",
  [281] = "CVR failed, decline, retain card",
  [282] = "TVR failed, decline, retain card",
  [283] = "ATC failed, decline, retain card",
  [284] = "Fallback check, decline, retain card",
  [300] = "Successful",
  [301] = "Not supported by receiver",
  [302] = "Unable to locate record on file",
  [303] = "Duplicate record, old record replaced",
  [304] = "Field edit error",
  [305] = "File locked out",
  [306] = "Not successful",
  [307] = "Format error",
  [308] = "Duplicate, new record rejected",
  [309] = "Unknown file",
  [400] = "Reversal accepted",
  [481] = "Reversal, original transaction not found",
  [484] = "Reversal, original transaction not approved",
  [500] = "Reconciled, in balance",
  [501] = "Reconciled, out of balance",
  [502] = "Amount not reconciled, totals provided",
  [503] = "Totals not available",
  [504] = "Not reconciled, totals provided",
  [600] = "Accepted",
  [601] = "Not able to trace back original transaction",
  [602] = "Invalid reference number",
  [603] = "Reference number/PAN incompatible",
  [604] = "POS photograph is not available",
  [605] = "Item supplied",
  [606] = "Request cannot be fulfilled—required/requested documentation is not available",
  [607] = "Out of window",
  [700] = "Accepted",
  [751] = "Approved, exceeded limit",
  [800] = "Accepted",
  [900] = "Advice acknowledged, no financial liability accepted",
  [901] = "Advice acknowledged, financial liability accepted",
  [902] = "Invalid transaction",
  [903] = "Re-enter transaction",
  [904] = "Format error",
  [905] = "Acquirer not supported by switch",
  [906] = "Cutover in process",
  [907] = "Card issuer or switch inoperative",
  [908] = "Transaction destination cannot be found for routing",
  [909] = "System malfunction",
  [910] = "Card issuer signed off",
  [911] = "Card issuer timed out",
  [912] = "Card issuer unavailable",
  [913] = "Duplicate transmission",
  [914] = "Not able to trace back to original transaction",
  [915] = "Reconciliation cutover or checkpoint error",
  [916] = "MAC incorrect",
  [917] = "MAC key synchronization error",
  [918] = "No communication keys available for use",
  [919] = "Encryption key synchronization error",
  [920] = "Security software/hardware error, try again",
  [921] = "Security software/hardware error, no action",
  [922] = "Message number out of sequence",
  [923] = "Request in progress",
  [940] = "Database error",
  [941] = "Currency code not supported",
  [942] = "Amount format error",
  [943] = "Customer/vendor format error",
  [944] = "Data format error",
  [945] = "Name format error",
  [946] = "Account format error",
  [947] = "Recurring data error",
  [948] = "Update not allowed",
  [949] = "Invalid capture (posting) date",
  [950] = "Violation of business arrangement",
  [992] = "Vendor authorization failed",
  [993] = "Vendor authorization rejected",
  [994] = "Vendor customer ID invalid",
  [995] = "Vendor customer account limit reached",
  [996] = "Vendor system unavailable"
  }

--[[list of the length of the data elements in the variable payload
    numbers show the lentgh of the fields
    99 is two digit veriable length fields
    999 are three digit variable length fields ]]--
local dataElementsLength = {
  16, 99, 6, 12, 12, 12, 10, 8, 8, 8,
  6, 12, 4, 4, 6, 4, 4, 4, 3, 3,
  3, 12, 3, 3, 4, 4, 1, 6, 3, 24,
  99, 99, 99, 99, 99, 99, 12, 6, 3, 3,
  16, 15, 99, 99, 99, 999, 999, 999, 3, 3,
  3, 16, 99, 999, 999, 99, 3, 99, 999, 999,
  999, 999, 999, 16 }

local function Log_It(logstr)
  if LogFlag > 0 then 
    amd.print(string.format("%s", logstr))
  end
end

local function toBinaryString(hexString)
  local bitStr = ''
  local j
  
  for j = 1, #hexString do                    --for the length of the string convert it to bits
  char = string.sub(hexString, j, j) 
  --Log_It ('char: '.. char)       
    if char == '0' then bitStr = bitStr .. "0000"
    elseif char == '1' then bitStr = bitStr .. "0001"
    elseif char == '2' then bitStr = bitStr .. "0010"
    elseif char == '3' then bitStr = bitStr .. "0011"
    elseif char == '4' then bitStr = bitStr .. "0100"
    elseif char == '5' then bitStr = bitStr .. "0101"
    elseif char == '6' then bitStr = bitStr .. "0110"
    elseif char == '7' then bitStr = bitStr .. "0111"
    elseif char == '8' then bitStr = bitStr .. "1000"
    elseif char == '9' then bitStr = bitStr .. "1001"
    elseif char == 'A' then bitStr = bitStr .. "1010"
    elseif char == 'B' then bitStr = bitStr .. "1011"
    elseif char == 'C' then bitStr = bitStr .. "1100"
    elseif char == 'D' then bitStr = bitStr .. "1101"
    elseif char == 'E' then bitStr = bitStr .. "1110"
    elseif char == 'F' then bitStr = bitStr .. "1111"
    end
  end
--  Log_It('BitStr: '.. bitStr)
  return bitStr
end

local function processDataElements(varPayload, bitStr, limit)
  local j
  local bit
  local codeLen
  local fCode = ''
  local aCode = 'notset'
  local uname = ''
  local offset = 1
  local varOffset = 0
  local stan 
  
  local fieldRange = limit and math.min(limit, #bitStr) or #bitStr 
    
  for j=1, fieldRange do                   --for the length of the bitStr which is the fixed payload in bits
    bit = string.sub(bitStr, j, j)      -- get the bit value
    if bit == '1' then                  -- if fixed field set then the variable data has information that must be processed
      if dataElementsLength[j] then     --make sure the length is retrieved from the dataelemtnslength table
        codeLen = dataElementsLength[j]  --set the codeLen to the value from the table
        if codeLen < 99 then              --for all non variable length elements
          if j == functionCodeBit then fCode = varPayload:sub(offset, offset+codeLen-1)    --when processing bit 24 get the function code
          elseif j == actionCodeBit then aCode = varPayload:sub(offset, offset+codeLen-1)    --when at processing 39 get the action code
          elseif j == usernameBit then 
            uname = varPayload:sub(offset, offset+codeLen-1)
            uname = uname:gsub("%s+", "")
            uname = uname:gsub("^0+", "")
          elseif j == stanBit then 
            stan = varPayload:sub(offset, offset+codeLen-1)
          end
        offset = offset + codeLen             --move the varpayload offset past the current field
        elseif codeLen == 99 then                                         --two digit variable length field
          varOffset = tonumber(string.sub(varPayload, offset, offset+1))  --get the length of the field from the first 2 digits in the field
          offset = offset + 2 + varOffset                                 --move the offset to after the length of the field
        elseif codeLen == 999 then                                         --two digit variable length field
          varOffset = tonumber(string.sub(varPayload, offset, offset+2))  --get the length of the field from the first 3 digits in the field
          offset = offset + 2 + varOffset                                 --move the offset to after the length of the field
        end
      else   --dataelement field not recognized
        Log_It('Error: data field length not recognized')
        stats:setAttribute(errorAttrib, 'Data Processing error - data element length field not recognized')  
      end      --processing the data elements and moving the offset
    end     --processing if a bit is set to 1
  end  --for - processing each bit in the bit string
  return fCode, aCode, uname, stan
end


function parse_request_unsafe(payload, stats)
  Log_It('--------------------------------------- Request Processing Started -----------------------------------------')
  local MTIno        --Message Type Identifier string
  local MTImsg       --MTI String converted to the MTI code associated with the number
  local operName = 'Unknown'     --Operation name will be set as unknown for now and pulled from the response
                     --this is in case the operation name is not set later, can't have task set with no operation name
  local taskName     --text used to set the CAS Task value
  
  if payload:len() == 0 then    --ensure there is some payload to process
    Log_It('No Request Payload to process')
    return 1
  end
  
  MTIno = string.sub(payload, MTIbeg, MTIend)     --pull the MTI code from the payload
  MTImsg = MTIcodes[tonumber(MTIno)]              --Look up the extracted MTI number to get the message string
  Log_It('MTI number is: ' .. MTIno)

  if MTImsg then                                  --if the message is retrieved using the MTI number  
    taskName = MTImsg .. ' (' .. MTIno .. ')'     --set the taskname for the CAS
    Log_It('Task Name: '.. taskName .. '\nOperation name: ' .. operName)
    stats:setParameter(taskParm, taskName)
  else                                            --Code lookup failed - no message associated with the MTI number
    taskName = "Unknown Message Type: " .. '(' .. MTIno .. ')'
    Log_It('MTI number not recognized\n Task Name: '.. taskName .. '\n Operation name: ' .. operName)
    stats:setParameter(taskParm, taskName)
  end
  stats:setOperationName(operName, operName:len())  --set operation name so a task is not set without an operation set
  
  Log_It('--------------------------------------- Request Processing Complete -----------------------------------------') 
  return 0  
end


function parse_response_unsafe(payload, stats)
  Log_It('--------------------------------------- Response Processing Started -----------------------------------------')
  local MTIno        --Message Type Identifier string
  local MTImsg       --MTI String converted to the MTI code associated with the number
  local operName = 'Unknown'     --Operation name will be set as unknown for now but will be set from function codes
  local taskName     --text used to set the CAS Task value
  local rejectedTask  --task set in the request that is recieved the 1644, rejected response       
  local fixedPayload
  local varPayload
  local attrNo
  local fixedPayloadBitStr
  local functionCode = ''                 --used to set the page name - number retrieved from payload
  local actionCode = ''                    --used to set the operation attribute - number retrieved from payload
  local uname = ''
  local functionMsg = ''                --text to set the function code
  local actionMsg = ''                  --text to set the action code
  local actionCodeNo = 0                --action code stored as a number
  local stan =''
      
  if payload:len() == 0 then    --ensure there is some payload to process
    Log_It('No Response Payload to process')
    return 1
  end

  taskName = stats:getParameter(taskParm)         --get the taskname that was set in the request processing
  MTIno = string.sub(payload, MTIbeg, MTIend)     --pull the MTI code from the payload
  MTImsg = MTIcodes[tonumber(MTIno)]              --Look up the extracted MTI number to get the message string
  Log_It('MTI number in response: ' .. MTIno)

  if not taskName then                            --if the taskname was not set in the process request it will be set from the response
    stats:setOperationName(operName, operName:len())  --set operation name so a task is not set without an operation set
    if MTImsg then                                  --if the message is retrieved using the MTI number from the response
      taskName = 'Unmatched Response: ' .. MTImsg .. ' (' .. MTIno .. ')'     --set the taskname for the CAS
      Log_It('MTI task name from response: '.. taskName)
      stats:setParameter(taskParm, taskName)
    else                                            --Code lookup failed - no message associated with the MTI number
      taskName = "Unmatched and Unknown Message Type: " .. '(' .. MTIno .. ')'
      Log_It('MTI number not recognized\n Task Name: '.. taskName)
      stats:setParameter(taskParm, taskName)
  end
  elseif MTIno == '1644' then               --Requested task recived a 1644 Code - Rejected message by the server
    rejectedTask = 'Rejected Message: ' .. taskName     --set the old task in the error OA
    taskName = MTImsg .. ' (' .. MTIno .. ')' .. ' - Rejected Message'    --set the new task name from response
    Log_It('Rejected Taskname: ' .. taskName .. '\nRejected message: ' .. rejectedTask)
    stats:setParameter(taskParm, taskName)                                --set task name
    stats:setAttribute(errorAttrib, rejectedTask)                         --set the error operation attribute for the CAS
  end
  Log_It('Taskname is: '.. taskName)

  fixedPayload = string.sub(payload, fixedPayloadBegin, varPayloadBegin-1) -- fixedpayload bitstring determines what fields are in the varPayload--
  varPayload = string.sub(payload, varPayloadBegin, payload:len()) --variable length payload - values of all the fields that are set
  fixedPayloadBitStr = toBinaryString(fixedPayload)   --fixed payload converted to bits to see which data fields exist
  Log_It('\tThe fixed payload is: ' .. fixedPayload .. '\n\tThe var payload is: ' .. varPayload .. '\n\tThe Fixed payload in bits is: ' .. fixedPayloadBitStr)

   --[[the functionCode and actionCode and usernames are in different positions depending on fixedPayload bitstring
       processDataElements retrieves the correct codes from the correct positions using the bitmap in the fixedpayload bitstring ]]--
  functionCode, actionCode, uname, stan = processDataElements(varPayload, fixedPayloadBitStr)
  Log_It('\tThe function code is: ' .. functionCode .. '\n\tThe action code is: ' .. actionCode .. '\n\tThe username is: ' .. uname)

  if (type(uname) == "string" and uname:len() > 0 and uname ~= '')  then    --check to see if username is set
--    Log_It('Username: '.. uname)
    stats:setUserName(uname)                                --pass back the username
  end  
  
  functionMsg = functionCodes[tonumber(functionCode)]     --lookup the functioncode number in the table and get the message text
  if functionMsg then                                       --for a successful lookup
    functionMsg = functionMsg .. ' (' .. functionCode .. ')'    --set the text to have the message and number
  else                                                       --function message not found from the code
    functionMsg = 'Unknown Function Code: ' .. '(' .. functionCode .. ')'
  end
  Log_It('Function Message: '.. functionMsg)
  stats:setOperationName(functionMsg, functionMsg:len())

  actionMsg = actionCodes[tonumber(actionCode)]           --lookup the action code number in the table and get the action text
  if actionMsg then                                       --if the message was retrieved
    actionMsg = actionMsg .. ' (' .. actionCode .. ')'    --set the action message to include the code number
    actionCodeNo = tonumber(actionCode)                   --convert the action code to a number instead of a string
    if actionCodeNo >= 100 and actionCodeNo <= 199  then  --determine which OA to set based on the action code number
      attrNo = denyAttrib
      elseif actionCodeNo >= 200 and actionCodeNo <= 299  then
      attrNo = denyRetainAttrib
      elseif actionCodeNo >= 301 and actionCodeNo <= 399  then
      attrNo = acceptAttrib
      elseif actionCodeNo >= 601 and actionCodeNo <= 699  then
      attrNo = warnAttrib
      elseif actionCodeNo >= 948 and actionCodeNo <= 949  then
      attrNo = warnAttrib
      elseif actionCodeNo >= 994 and actionCodeNo <= 995  then
      attrNo = warnAttrib
      elseif actionCodeNo >= 902 and actionCodeNo <= 922  then
      attrNo = warnAttrib
      elseif actionCodeNo >= 950 and actionCodeNo <= 993  then
      attrNo = warnAttrib
      elseif actionCodeNo == 940 or actionCodeNo == 947 or actionCodeNo == 996 then
      attrNo = errorAttrib
      else
      attrNo = acceptAttrib
    end    
  else      --action code not matched in the action message table
    if actionCode ~= 'notset' then
      actionMsg = 'Unknown Action Code' .. ' (' .. actionCode .. ')'
      attrNo = errorAttrib
    else
      actionMsg = 'Action Code: ' .. actionCode
      attrNo = warnAttrib
    end
  end
  Log_It('Action Mesage: ' .. actionMsg .. '\tAttribute Number' .. attrNo)
  stats:setAttribute(attrNo, actionMsg)
  Log_It('--------------------------------------- Response Processing Complete -----------------------------------------') 
  return 0  
end




function messageHandlers()
  return {"IsoMessages", "IsoHits"}
end

IsoMessages = {}
IsoHits = {}

function IsoHits.trySync()
  return true
end

function IsoHits.processDirectionSwitch(mh)
end

function IsoHits.parseMessage(mh)
  mh:messageComplete(mh:currentBlock():length())
    
  local payload = mh:currentBlock():c_str()
  local request = payload:sub(5,5) == '0' or payload:sub(5,5) == '2' or payload:sub(5,5) == '4'
            
  
  mh:setRequest(request)
  mh:setResponse(not request)
  if not request then mh:setLast() end
  
  mh:pushNextLayerRange(0,mh:currentBlock():length())
  
end

function IsoMessages.trySync(inBlock)
  local payload = inBlock:c_str()
  
  -- message length less than 0x0fff (4095) bytes and  version 1993 and (request or  advice or notification)  
  return (payload:len() > 16 and  payload:byte(1) <= 0xf  and payload:sub(3,3) ==  '1'  and
            ( 
              payload:sub(5,5) == '0'
              or payload:sub(5,5) == '2' 
              or payload:sub(5,5) == '4'
            )
          )  
   
end

function IsoMessages.processDirectionSwitch(mh)
end

function IsoMessages.parseMessage(mh)
  if mh:currentBlock():length() < 16 then
    mh:needMore(16)
    return
  end
  
  local payload = mh:currentBlock():c_str()
  local l = struct.unpack(">I2",payload:sub(1,2))
  
  if l >  0xfff then
    mh:setBroken()
    return
  end  
  
  if mh:currentBlock():length() < l+2 then
    mh:needMore(l+2)
    return
  end
  
  if payload:sub(3,3) ~=  '1' then
    mh:setBroken()
    return
  end  
  
  
  
  local result, message = pcall( function ()
      local fixedPayload = string.sub(payload, fixedPayloadBegin, varPayloadBegin-1) -- fixedpayload bitstring determines what fields are in the varPayload--
      local varPayload = string.sub(payload, varPayloadBegin, payload:len()) --variable length payload - values of all the fields that are set
      local fixedPayloadBitStr = toBinaryString(fixedPayload)   --fixed payload converted to bits to see which data fields exist
      local functionCode, actionCode, uname, stan = processDataElements(varPayload, fixedPayloadBitStr, stanBit)
      mh:setYahaSessionId(stan)
    end)
  if not result then
    amd.print("ERROR" .. message)
    mh:setBroken()
    return  
  end
    
  mh:messageComplete(l+2)
  mh:pushNextLayerRange(0,l+2)
  
end

function parse_request(payload, stats)
  local result, message = pcall(parse_request_unsafe, payload,stats)
  
  if not result then
    amd.print("Parsing error: " .. message)
    stats:setOperationName("INVALID", string.len("INVALID"))
  end 
  
end

function parse_response(payload, stats)
  local result, message = pcall(parse_response_unsafe, payload,stats)
  
  if not result then
    amd.print("Parsing error: " .. message)
    stats:setOperationName("INVALID", string.len("INVALID"))
  end 
  
end

local the_module = {}
the_module.parse_request = parse_request
the_module.parse_response = parse_response
return the_module
