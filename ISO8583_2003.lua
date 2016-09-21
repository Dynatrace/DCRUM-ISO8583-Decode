--[[
Copyright © 2015 Dynatrace LLC. 
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

-- script name --
function script_name()
  return "ISO8583_2003"
end

function toBinaryString(hexString)
  for j = 1, hexLen do
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
  Log_It('BitStr: '.. bitStr)
  return bitStr
end

function processDataElement(pload, j, offset)
  Log_It('Data element code to process: ' .. j)
    
  if dataElementsLength[tonumber(j)] then
	local codeLen = dataElementsLength[tonumber(j)]
	Log_It('Data element code length: ' .. codeLen)
	
	if j == 2 then functionCode = pload:sub(offset, offset+codeLen-1)
	elseif j == 26 then merchantCode = pload:sub(offset, offset+codeLen-1)
	elseif j == 39 then bankCode = pload:sub(offset, offset+codeLen-1)
	elseif j == 48 then responseCode = pload:sub(offset, offset+codeLen-1)
	elseif j == 12 then datetime = pload:sub(offset, offset+codeLen-1)
	end
	offSet = offSet + codeLen
  else
    Log_It('Error: Data element code not recognized')
  end  
end

function Log_It(logstr)
  if LogFlag > 0 then 
	amd.print(string.format("%s", logstr))
  end
end

  LogFlag = 0 --Set this flag to 1 to enable logging diagnostic data
  hexLen = 0
  bitStr = ''
  bitLen = 0
  offSet = 0
  operName = ''
  MTIstr  = ''
  functionCode = ''
  merchantCode = ''
  bankCode = ''
  responseCode = ''
  datetime = ''
  
  MTIcodes = {
    [2100] = "Inquiry",
    [2110] = "Inquiry",
	[2200] = "Payment",
    [2210] = "Payment",
	[2300] = "Advice",
	[2310] = "Advice"
  }
  
  dataElementsLength = { 
	[2] = 5, --transaction typpe
	[4] = 16, --ignore
	[11] = 12, --ignore
	[12] = 14, --date & time
	[15] = 8, --date
	[26] = 4, --merchant code
	[32] = 2, --igonre
	[39] = 7, --bank code
	[48] = 4 --response code
  }
      
 function parse_request(payload, stats)
   
  Log_It('Parse Request')
  if payload:len() == 0 then
    return 1
  end
   
  MTIstr = string.sub(payload, 1, 4) --Message Type Identifier
  if MTIcodes[tonumber(MTIstr)] then
	Log_It('MTI Operation Name: ' .. MTIcodes[tonumber(MTIstr)])
	operName = MTIcodes[tonumber(MTIstr)]
	stats:setOperationName(operName, operName:len())
  else
    amd.print(string.format("Message Type Identifier code not recognized: %s", MTIstr))
	operName = 'Unknown operation (' .. MTIstr .. ')'
	stats:setOperationName(operName, operName:len())
  end
  
  Log_It('EXTENDED PARSING OF REQUEST IS CURRENTLY DISABLED - ALL DATA IS EXTRACTED FROM RESPONSE')
  Log_It('--------------------------------------- Request Processing Complete -----------------------------------------') 
  return 0
end

 function parse_response(payload, stats)
  Log_It('Parse_Response')
  if payload:len() == 0 then
    return 1
  end

  bitStr = ''
  pgmStr =''
  functionCode = ''
  merchantCode = ''
  bankCode = ''
  responseCode = ''
  datetime = ''
  
  MTIstr = string.sub(payload, 1, 4) --Message Type Identifier 
  if MTIcodes[tonumber(MTIstr)] then
	Log_It('MTI Operation Name: ' .. MTIcodes[tonumber(MTIstr)])
	operName = MTIcodes[tonumber(MTIstr)]
	stats:setOperationName(operName, operName:len())
  else
    amd.print(string.format("Message Type Identifier code not recognized: %s", MTIstr))
	operName = 'Unknown operation (' .. MTIstr .. ')'
	stats:setOperationName(operName, operName:len())
  end
 
  Log_It('Payload len: ' .. payload:len()) 
  Log_It('Payload: ' .. string.sub(payload, 5, payload:len()))

  primaryBitmapStr = string.sub(payload, 5, 20) --extract primary bitmap (currently we dont find anything interesting to report from secondary bitmap)
  hexLen = 16  
  bitLen = 64 
  offSet = 23
  Log_It ('Primary bitmap: '.. primaryBitmapStr)
  bitStr = toBinaryString(primaryBitmapStr)

  for j=1, bitLen do
    bit = string.sub(bitStr, j, j)
    if bit == '1' then
	  processDataElement(payload, j, offSet)
    end     
  end  
  
  if tonumber(functionCode) then
	Log_It('Function code:' .. functionCode)
	stats:setParameter(0, functionCode)
  else
    Log_It('Error: Function code not recognized: ' .. functionCode)
    --stats:setParameter(0, 'Function code not recognized (' .. functionCode .. ')')
  end
  
  if tonumber(merchantCode) then
	Log_It('Merchant code:' .. merchantCode)
	stats:setParameter(1, merchantCode)
  else
    Log_It('Error: Merchant code not recognized: ' .. merchantCode)
    --stats:setParameter(1, 'Merchant code not recognized (' .. merchantCode .. ')')
  end
  
  if bankCode:len() == 7 then
	Log_It('Bank code:' .. bankCode)
	stats:setParameter(2, bankCode)
  else
    Log_It('Error: Bank code not recognized: ' .. bankCode)
    --stats:setParameter(2, 'Bank code not recognized (' .. bankCode .. ')')
  end
    
  if tonumber(responseCode) then
	if tonumber(responseCode) ~= 0 then
		Log_It('Response code:' .. responseCode)
		stats:setAttribute(0, responseCode)
	end
  else
    Log_It('Error: Response code not recognized: ' .. responseCode)
    --stats:setParameter(0, 'Response code not recognized (' .. responseCode .. ')')
  end

  if datetime:len() == 14 then
     stats:setAttribute(1, datetime)
  end
  
  Log_It('####################################### Response Processing Complete ########################################') 
  return 0
end

local the_module = {}
the_module.parse_request = parse_request
the_module.parse_response = parse_response
return the_module
