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
  return "ISO8583Parser"
end

function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

function MTI_Name(wrkstr)
  operName = ''
  if wrkstr == "0100" then operName = "Authorization Request - "..wrkstr    
  elseif wrkstr == "0110" then operName = "Request Response - "..wrkstr   
  elseif wrkstr == "0120" then operName = "Authorization Advice - "..wrkstr
  elseif wrkstr == "0121" then operName = "Authorization Advice Repeat - "..wrkstr
  elseif wrkstr == "0130" then operName = "Issuer Response to Authorization Advice - "..wrkstr
  elseif wrkstr == "0200" then operName = "Acquirer Financial Request - "..wrkstr
  elseif wrkstr == "0210" then operName = "Issuer Response to Financial Request - "..wrkstr
  elseif wrkstr == "0220" then operName = "Acquirer Financial Advice - "..wrkstr
  elseif wrkstr == "0221" then operName = "Acquirer Financial Advice repeat - "..wrkstr
  elseif wrkstr == "0230" then operName = "Issuer Response to Financial Advice - "..wrkstr
  elseif wrkstr == "0320" then operName = "Batch Upload - "..wrkstr
  elseif wrkstr == "0330" then operName = "Batch Upload Response - "..wrkstr
  elseif wrkstr == "0400" then operName = "Acquirer Reversal Request - "..wrkstr
  elseif wrkstr == "0420" then operName = "Acquirer Reversal Advice - "..wrkstr
  elseif wrkstr == "0421" then operName = "Acquirer Reversal Advice Repeat Message - "..wrkstr
  elseif wrkstr == "0500" then operName = "Batch Settlement request - "..wrkstr
  elseif wrkstr == "0510" then operName = "Batch Settlement response - "..wrkstr
  elseif wrkstr == "0800" then operName = "Network Management Request - "..wrkstr
  elseif wrkstr == "0810" then operName = "Network Management Response - "..wrkstr
  elseif wrkstr == "0820" then operName = "Keychange - "..wrkstr
  else operName = "??????" 
  end
end

function Log_It(logstr)
  if LogFlag > 0 then 
    print('Logging: '..logstr)
  end
end

local function unpack_number(pstr, offset, size)
  local number = 0
  local max = size - 1
  
  for i = 0, max do
    number = number * 256
    number = (number + pstr:byte(offset + i))
  end
  return number
end

local function unpack_length(pstr, offset, size)
  local number = 0
  local offset2 = offset + size -1
  local max = size - 1
  for i = 0, max do
    number = number * 256
    number = (number + pstr:byte(offset2 - i))
  end
  return number
end

function case_2(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('02 -- Account len: '.. x ..' Account # '..pstr:sub(offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_3(pstr, offset)
  Log_It('03 -- Procesing Code: ' .. string.sub(pstr, offset, offset+5))
  offSet = offSet + 6
  return 0
end

function case_4(pstr, offset)
  Log_It('04 -- Amount - Transaction: ' .. string.sub(pstr, offset, offset+11))
  offSet = offSet + 12
  return 0
end

function case_5(pstr, offset)
  Log_It('05 -- Amount - Settlement: ' .. string.sub(pstr, offset, offset+11))
  offSet = offSet + 12
  return 0
end

function case_6(pstr, offset)
  Log_It('06 -- Amount - Cardholder Billing: ' .. string.sub(pstr, offset, offset+11))
  offSet = offSet + 12
  return 0
end

function case_7(pstr, offset)
  Log_It('07 -- Transmission date& time: ' .. string.sub(pstr, offset, offset+9))
  offSet = offSet + 10
  return 0
end
function case_8(pstr, offset)
  Log_It('08 -- Amount - Cardholder Billing Fee: ' .. string.sub(pstr, offset, offset+7))
  offSet = offSet + 8
  return 0
end

function case_9(pstr, offset)
  Log_It('09 -- Conversion rate, Settlement: ' .. string.sub(pstr, offset, offset+7))
  offSet = offSet + 8
  return 0
end

function case_10(pstr, offset)
  Log_It('10 -- Conversion rate, cardholder billing: ' .. string.sub(pstr, offset, offset+7))
  offSet = offSet + 8
  return 0
end

function case_11(pstr, offset)
  Log_It('11 -- System rtrace audit number: ' .. string.sub(pstr, offset, offset+5))
  offSet = offSet + 6
  return 0
end

function case_12(pstr, offset)
  Log_It('12 -- Time, local transcaton (hhmmss) ' .. string.sub(pstr, offset, offset+5))
  offSet = offSet + 6
  return 0
end

function case_13(pstr, offset)
  Log_It('13 -- Date, local transaction (MMDD): ' .. string.sub(pstr, offset, offset+3))
  offSet = offSet + 4
  return 0
end

function case_14(pstr, offset)
  Log_It('14 -- Date, expiration: ' .. string.sub(pstr, offset, offset+3))
  offSet = offSet + 4
  return 0
end

function case_15(pstr, offset)
  Log_It('15 -- Date, settlement: ' .. string.sub(pstr, offset, offset+3))
  offSet = offSet + 4
  return 0
end

function case_16(pstr, offset)
  Log_It('16 -- Date, conversion: ' .. string.sub(pstr, offset, offset+3))
  offSet = offSet + 4
  return 0
end

function case_17(pstr, offset)
  Log_It('17 -- Date, capute: ' .. string.sub(pstr, offset, offset+3))
  offSet = offSet + 4
  return 0
end

function case_18(pstr, offset)
  Log_It('18 -- Merchant type: ' .. string.sub(pstr, offset, offset+3))
  offSet = offSet + 4
  return 0
end

function case_19(pstr, offset)
  Log_It('19 -- Aquiring Country code: ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3
  return 0
end

function case_20(pstr, offset)
  Log_It('20 -- PAN extended country code: ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3
  return 0
end

function case_21(pstr, offset)
  Log_It('21 -- Forwarding institution country code: ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3
  return 0
end

function case_22(pstr, offset)
  Log_It('22 -- Point of service entry mode: ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3
  return 0
end

function case_23(pstr, offset)
  Log_It('23 -- Application PAN sequence number: ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3
  return 0
end

function case_24(pstr, offset)
  Log_It('24 -- Function Code : ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3
  return 0
end

function case_25(pstr, offset)
  Log_It('25 -- Point of service condition code: ' .. string.sub(pstr, offset, offset+1))
  offSet = offSet + 2
  return 0
end

function case_26(pstr, offset)
  Log_It('26 -- Point of service capture code: ' .. string.sub(pstr, offset, offset+1))
  offSet = offSet + 2
  return 0
end

function case_27(pstr, offset)
  Log_It('27 -- Authorizing ID responce length: ' .. string.sub(pstr, offset, offset))
  offSet = offSet + 1
  return 0
end

function case_28(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('28 -- Len: '.. x ..' Amount Transaction fee: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_29(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('29 -- Len: '.. x ..' Amount Settlement fee: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_30(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('30 -- Len: '.. x ..' Amount Transaction Processing fee: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_31(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('31 -- Len: '.. x ..' Amount settlement Processing fee: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_32(pstr, offset) 
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('32 -- Len: '.. x ..' Acquiring Institution ID code: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end
function case_33(pstr, offset) 
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('33 -- Len: '.. x ..' Forwarding Institution ID code: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_34(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('34 -- Len: '.. x ..' Primary account number extended: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_35(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('35 -- Len: '.. x ..' Track 2 Data: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_36(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('36 -- Len: '.. x ..' Track 3 Data: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_37(pstr, offset)
  Log_It('37 -- Retrieval reference number: ' .. string.sub(pstr, offset, offset+11))
  offSet = offSet + 12
  return 0
end

function case_38(pstr, offset)
  Log_It('38 -- Authorization identification responce: ' .. string.sub(pstr, offset, offset+5))
  offSet = offSet + 6 
  return 0
end

function case_39(pstr, offset)
  Log_It('39 -- Response Code: ' .. string.sub(pstr, offset, offset+1))
  retCode = pstr:sub(offset, offset+1)
  offSet = offSet + 2
  return 0
end

function case_40(pstr, offset)
  Log_It('40 -- Service Restriction code: ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3
  return 0
end

function case_41(pstr, offset)
  Log_It('41 -- Card acceptor terminal ID: ' .. string.sub(pstr, offset, offset+7))
  offSet = offSet + 8
  return 0
end

function case_42(pstr, offset) 
  Log_It('42 -- Card acceptor ID code: ' .. string.sub(pstr, offset, offset+14))
  uname = pstr:sub(offset, offset+14)
  uname = uname:gsub("%s+", "")
  uname = uname:gsub("^0+", "")
  Log_It('---uname:'.. uname);
  offSet = offSet + 15
  return 0
end

function case_43(pstr, offset)
  Log_It('43 -- Card acceptor name/location: ' .. string.sub(pstr, offset, offset+39))
  offSet = offSet + 40
  return 0
end

function case_44(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('44 -- Len: '.. x ..' Additional responce data: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_45(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('45 -- Len: '.. x ..' Track 1 Data: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_46(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('46 -- Len: '.. x ..' Additional Data ISO: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_47(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('47 -- Len: '.. x ..' Additional Data national: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_48(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('48 -- Len: '.. x ..' Additional Data private: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_49(pstr, offset)
  Log_It('49 -- Currency code transcation: ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3 
  return 0
end

function case_50(pstr, offset)
  Log_It('50 -- Currency code settlement: ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3
  return 0
end

function case_51(pstr, offset)  
  Log_It('51 -- Currency code cardholder: ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3 
  return 0
end

function case_52(pstr, offset)
  Log_It('52 hex-:'.. string.tohex(string.sub(pstr, offset, offset+15))) 
  Log_It('52 -- Personal ID number data: ' .. string.sub(pstr, offset, offset+15))
  offSet = offSet + 16
  return 0
end

function case_53(pstr, offset)
  Log_It('53 -- Security related control infomation: ' .. string.sub(pstr, offset, offset+15))
  offSet = offSet + 14; 
  return 0
end

function case_54(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('54 -- Len: '.. x ..' Additional amounts: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_55(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('55 -- Len: '.. x ..' Reserved ISO: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_56(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('56 -- Len: '.. x ..' Reserved ISO: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_57(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('57 -- Len: '.. x ..' Reserved national: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_58(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('58 -- Len: '.. x ..' Reserved national: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_59(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('59 -- Len: '.. x ..' Reserved national: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_60(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('60 -- Len: '.. x ..' Reserved national: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_61(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('61 -- Len: '.. x ..' Reserved private: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_62(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('62 -- Len: '.. x ..' Reserved private: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_63(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('63 -- Len: '.. x ..' Reserved private: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_64(psrt, offset)
   Log_It('64 -- MAC: ' .. string.sub(pstr, offset, offset+3))
  offSet = offSet + 4
  return 0
  end

function case_65(pstr, offset)
  Log_It('65 -- Bitmap: ' .. string.sub(pstr, offset, offset))
  offSet = offSet + 1
  return 0
end

function case_66(pstr, offset)
  Log_It('66 -- Settlement Code: ' .. string.sub(pstr, offset, offset))
  offSet = offSet + 1
  return 0
end

function case_67(pstr, offset)
  Log_It('67 -- Extend payment Code: ' .. string.sub(pstr, offset, offset+1))
  offSet = offSet + 2
  return 0
end

function case_68(pstr, offset)
  Log_It('68 -- receiving country Code: ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3
  return 0
end

function case_69(pstr, offset)
  Log_It('69 -- settlement country Code: ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3
  return 0
end

function case_70(pstr, offset)
  Log_It('70 -- network management information code: ' .. string.sub(pstr, offset, offset+2))
  offSet = offSet + 3
  return 0
end

function case_71(pstr, offset)
  Log_It('71 -- Message number: ' .. string.sub(pstr, offset, offset+3))
  offSet = offSet + 4
  return 0
end

function case_72(pstr, offset)
  Log_It('72 -- message number last: ' .. string.sub(pstr, offset, offset+3))
  offSet = offSet + 4
  return 0
end

function case_73(pstr, offset)
  Log_It('73 -- Date: ' .. string.sub(pstr, offset, offset+5))
  offSet = offSet + 6
  return 0
end

function case_74(pstr, offset)
  Log_It('74 -- Credits number: ' .. string.sub(pstr, offset, offset+9))
  offSet = offSet + 10
  return 0
end

function case_75(pstr, offset)
  Log_It('75 -- Credits recersal number: ' .. string.sub(pstr, offset, offset+9))
  offSet = offSet + 10
  return 0
end

function case_76(pstr, offset)
  Log_It('76 -- Debits number: ' .. string.sub(pstr, offset, offset+9))
  offSet = offSet + 10 
  return 0
end

function case_77(pstr, offset)
  Log_It('77 -- Debits reveral number: ' .. string.sub(pstr, offset, offset+9))
  offSet = offSet + 10 
  return 0
end

function case_78(pstr, offset)
  Log_It('78 -- Transfer Number: ' .. string.sub(pstr, offset, offset+9))
  offSet = offSet + 10 
  return 0
end

function case_79(pstr, offset)
  Log_It('78 -- Transfer Reversal Number: ' .. string.sub(pstr, offset, offset+9))
  offSet = offSet + 10 
  return 0
end

function case_80(pstr, offset)
  Log_It('80 -- Inquiries Number: ' .. string.sub(pstr, offset, offset+9))
  offSet = offSet + 10 
  return 0
end

function case_81(pstr, offset)
  Log_It('81 -- Authorizations Number: ' .. string.sub(pstr, offset, offset+9))
  offSet = offSet + 10 
  return 0
end

function case_82(pstr, offset)
  Log_It('82 -- Credit Proessing fee amount: ' .. string.sub(pstr, offset, offset+11))
  offSet = offSet + 12 
  return 0
end

function case_83(pstr, offset)
  Log_It('83 -- Credit transaction fee amount: ' .. string.sub(pstr, offset, offset+11))
  offSet = offSet + 12
  return 0
end

function case_84(pstr, offset)
  Log_It('84 -- Debits Proessing fee amount: ' .. string.sub(pstr, offset, offset+11))
  offSet = offSet + 12
  return 0
end

function case_85(pstr, offset)
  Log_It('85 -- Debits Transaction fee amount: ' .. string.sub(pstr, offset, offset+11))
  offSet = offSet + 12
  return 0
end

function case_86(pstr, offset)
  Log_It('86 -- Credits  amount: ' .. string.sub(pstr, offset, offset+15))
  offSet = offSet + 16
  return 0
end

function case_87(pstr, offset)
  Log_It('87 -- Credits reversal amount: ' .. string.sub(pstr, offset, offset+15))
  offSet = offSet + 16
  return 0
end

function case_88(pstr, offset)
  Log_It('88 -- Debits  amount: ' .. string.sub(pstr, offset, offset+15))
  offSet = offSet + 16
  return 0
end

function case_89(pstr, offset)
  Log_It('89 -- Debits reversal amount: ' .. string.sub(pstr, offset, offset+15))
  offSet = offSet + 16
  return 0
end

function case_90(pstr, offset)
  Log_It('90 -- Original data elements ' .. string.sub(pstr, offset, offset+41))
  offSet = offSet + 42
  return 0
end

function case_91(pstr, offset)
  Log_It('91 -- File update code: ' .. string.sub(pstr, offset, offset))
  offSet = offSet + 1
  return 0
end

function case_92(pstr, offset)
  Log_It('92 -- File security code: ' .. string.sub(pstr, offset, offset+1))
  offSet = offSet + 2
  return 0
end
function case_93(pstr, offset)
  Log_It('93 -- Responce indicator: ' .. string.sub(pstr, offset, offset+4))
  offSet = offSet + 5
  return 0
end

function case_94(pstr, offset)
  Log_It('94 -- Service indicator: ' .. string.sub(pstr, offset, offset+6))
  offSet = offSet + 7
  return 0
end

function case_95(pstr, offset)
  Log_It('95 -- replacement amounts: ' .. string.sub(pstr, offset, offset+41))
  offSet = offSet + 42
  return 0
end

function case_96(pstr, offset)
  Log_It('------ special check data --------')
  Log_It('96 -- Message security code: ' .. string.sub(pstr, offset, offset+7))
  offSet = offSet + 8
  return 0
end

function case_97(pstr, offset)
  Log_It('97 -- Amount net settlement: ' .. string.sub(pstr, offset, offset+15))
  offSet = offSet + 16
  return 0
end

function case_98(pstr, offset)
  Log_It('98 -- Payee: ' .. string.sub(pstr, offset, offset+24))
  offSet = offSet + 25
  return 0
end

function case_99(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('99 -- Len: '.. x ..' Settlement ID code: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_100(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('100 -- Len: '.. x ..' Receiving ID code: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_101(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('101 -- Len: '.. x ..' File name: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_102(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('102 -- Len: '.. x ..' Account ID 1 '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_103(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('103 -- Len: '.. x ..' Account ID 2 '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_104(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('104 -- Len: '.. x ..' Transaction Description '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_105(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('105 -- Len: '.. x ..'Reserved for ISO '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_106(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('106 -- Len: '.. x ..'Reserved for ISO '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
end

function case_107(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('107 -- Len: '.. x ..'Reserved for ISO '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_108(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('108 -- Len: '.. x ..'Reserved for ISO '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_109(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('109 -- Len: '.. x ..'Reserved for ISO '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_110(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('110-- Len: '.. x ..'Reserved for ISO '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_111(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('111 -- Len: '.. x ..'Reserved for ISO '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_112(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('112 -- Len: '.. x ..'Reserved for national '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_113(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('113 -- Len: '.. x ..'Reserved for national '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_114(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('114 -- Len: '.. x ..'Reserved for national '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_115(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('115 -- Len: '.. x ..'Reserved for national '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_116(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('116 -- Len: '.. x ..'Reserved for national '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_117(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('117 -- Len: '.. x ..'Reserved for national '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_118(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('118 -- Len: '.. x ..'Reserved for national '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_119(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('119 -- Len: '.. x ..'Reserved for national '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_120(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('120 -- Len: '.. x ..'Reserved for private: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_121(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('121 -- Len: '.. x ..'Reserved for private: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_122(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('122 -- Len: '.. x ..'Reserved for private: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_123(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('123 -- Len: '.. x ..'Reserved for private: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_124(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('124 -- Len: '.. x ..'Reserved for private: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_125(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('125 -- Len: '.. x ..'Reserved for private: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_126(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('126 -- Len: '.. x ..'Reserved for private: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_127(pstr, offset)
  local x = tonumber(string.sub(pstr, offset, offset+1))
  Log_It('127 -- Len: '.. x ..'Reserved for private: '..string.sub(pstr, offset+2, offset+1+x))
  offSet = offSet + 2 + x
  return 0
end

function case_128(pstr, offset)
  Log_It('------ special check data --------')
  Log_It('128 -- Message auth code: ' .. string.sub(pstr, offset, offset+7))
  offSet = offSet + 8
  return 0
end

function findfunction(x)
  assert(type(x) == "string")
  local f=_G
  for v in x:gmatch("[^%.]+") do
    if type(f) ~= "table" then
       Log_It('---nil one')
       return nil, "looking for '"..v.."' expected table, not "..type(f)
    end
    f=f[v]
  end
  if type(f) == "function" then
    return f
  else
    Log_It('---nil TWO')
    return nil, "expected function, not "..type(f)
  end
end

  LogFlag = 0
  hexChar = 0
  hexLen = 0
  hexStr = ''
  bitStr = ''
  bitLen = 0
  offSet = 0
  uname = ''
  IDcode = ''
  operName = ''
  MTIstr  = ''
  ClientType = ''
  ClientTypeStr= ''
  MsgClass = ''
  retCode = ''
  
 function parse_request(payload, stats)

  Log_It('Parse Request')
  if payload:len() == 0 then
    return 1
  end
  
  uname = ''
  ClientType = ''
  ClientTypeStr = ''
  MsgClass = ''
  MsgClassStr = ''
  bitStr = ''
  pgmStr =''
  xstr = ''
  
  Log_It('------------------------------------------------------------------------------------------------------') 
  Log_It('FF------:'.. string.tohex(string.sub(payload, 1, 1)))
  Log_It('Len hex-:'.. string.tohex(string.sub(payload, 2, 3))) 
  Log_It('Len-----:'.. unpack_length(payload, 2, 2) )
  MTIstr = string.sub(payload, 4, 7)
  MTI_Name(MTIstr)
  
  if operName == "??????" then 
    print('ISO8583 -- Invalid MTI:' .. string.tohex(MTIstr))
    print(' Request PL len--:'.. payload:len()) 
    print(' Request payload-:'.. string.tohex(payload:sub(0, payload:len())))  
    return 1
  end 
  

  Log_It('MTI-----:'..operName)    
  stats:setOperationName(operName, operName:len())
 
  ClientType =  string.sub(payload, 7, 7)
    
  if ClientType == "0" then ClientTypeStr = "Acquirer"   
    elseif ClientType == "1" then ClientTypeStr = "Acquirer Repeat"   
    elseif ClientType == "2" then ClientTypeStr = "Issuer" 
    elseif ClientType == "3" then ClientTypeStr = "Issuer Repeat"  
    elseif ClientType == "4" then ClientTypeStr = "Other"    
    elseif ClientType == "5" then ClientTypeStr = "Other Repeat"  
    else ClientTypeStr = "Unknown"  
  end
  stats:setBrowserOsHardware(ClientTypeStr, "", "", "")
    
    
  MsgClass   =  string.sub(payload, 5, 5)
  if MsgClass == "1" then MsgClassStr = "Authorization Message"  
    elseif MsgClass == "2" then MsgClassStr = "Financial Message"  
    elseif MsgClass == "3" then MsgClassStr = "File Actions Message"   
    elseif MsgClass == "4" then MsgClassStr = "Reversal and Chargeback Message"   
    elseif MsgClass == "5" then MsgClassStr = "Reconciliation Message"   
    elseif MsgClass == "6" then MsgClassStr = "Administrative Message"
    elseif MsgClass == "7" then MsgClassStr = "Fee Collection Message"
    elseif MsgClass == "8" then MsgClassStr = "Network Management Message" 
    elseif MsgClass == "9" then MsgClassStr = "Reserved By ISO" 
    else MsgClassStr = "Unknown"
  end
  stats:setParameter(4, MsgClassStr) 
  
  Log_It('PL len--:'.. payload:len()) 
  Log_It('payload-:'.. string.tohex(payload:sub(0, payload:len())))

  if payload:byte(8) < 128 then
    hexStr = string.tohex(string.sub(payload, 8, 15))
    hexLen = 16  
    bitLen = 64 
    offSet = 16
    Log_It ('8 byte mask: '.. hexStr) 
  else 
    hexStr = string.tohex(string.sub(payload, 8, 23))
    hexLen = 32
    bitLen = 128
    offSet = 24
    Log_It ('16 byte mask: '.. hexStr)
  end
 
   for j = 1, hexLen do
    hexChar = hexStr:byte(j) 
         
    if hexChar == 48 then  bitStr = bitStr .. "0000"
    elseif hexChar == 49 then bitStr = bitStr .. "0001"
    elseif hexChar == 50 then bitStr = bitStr .. "0010"
    elseif hexChar == 51 then bitStr = bitStr .. "0011"
    elseif hexChar == 52 then bitStr = bitStr .. "0100"
    elseif hexChar == 53 then bitStr = bitStr .. "0101"
    elseif hexChar == 54 then bitStr = bitStr .. "0110"
    elseif hexChar == 55 then bitStr = bitStr .. "0111"
    elseif hexChar == 56 then bitStr = bitStr .. "1000"
    elseif hexChar == 57 then bitStr = bitStr .. "1001"
    elseif hexChar == 65 then bitStr = bitStr .. "1010"
    elseif hexChar == 66 then bitStr = bitStr .. "1011"
    elseif hexChar == 67 then bitStr = bitStr .. "1100"
    elseif hexChar == 68 then bitStr = bitStr .. "1101"
    elseif hexChar == 69 then bitStr = bitStr .. "1110"
    else                    bitStr = bitStr .. "1111"
    end
  end
  
  Log_It('BitStr: '.. bitStr)
    
  for j=1, bitLen do
    hexChar = bitStr:byte(j) 
    if hexChar == 49 then
      if j > 1 then 
        xstr = xstr .. ", "
      end
      xstr = xstr .. j     
    end     
  end  
 
  Log_It('codes to process: '.. xstr) 
 
  if MTIstr == "0800" or MTIstr == "0810" then
    bitLen = 75
  else 
    bitLen = 49
  end
  
  for j=2, bitLen do
    hexChar = bitStr:byte(j) 
    if hexChar == 49 then
      pgmStr = 'case_' .. j
      fun = findfunction(pgmStr)
      if (fun == nil) then
        Log_It('error no function for:'..j)
      else
        fun(payload, offSet)
      end
    end     
  end  
  Log_It('---uname:'.. uname);
  stats:setUserName(uname)
  Log_It('------------------------------------------------------------------------------------------------------') 
  return 0
end

 function parse_response(payload, stats)
  Log_It('Parse_Response')
  if payload:len() == 0 then
    return 1
  end

  uname = ''
  bitStr = ''
  pgmStr =''
  xstr = '' 
  retCode = ''
  
  Log_It('######################################################################################################') 
  Log_It('FF------:'.. string.tohex(string.sub(payload, 1, 1)))
  Log_It('Len hex-:'.. string.tohex(string.sub(payload, 2, 3))) 
  Log_It('Len-----:'.. unpack_length(payload, 2, 2) )
  MTIstr = string.sub(payload, 4, 7)
  Log_It('MTI-----:'.. MTIstr)
  MTI_Name(MTIstr)  
  Log_It('MTI-----:'..operName)

  if operName == "??????" then 
    print('ISO8583 -- Invalid MTI:' .. string.tohex(MTIstr))
    print('  Responce PL len--:'.. payload:len()) 
    print('  Responce payload-:'.. string.tohex(payload:sub(0, payload:len())))  
    return 1
  end 

  Log_It('MTI-----:'..operName)
 -- stats:setOperationName(operName, operName:len())
  
  Log_It('PL len--:'.. payload:len()) 
  Log_It('payload-:'.. string.tohex(payload:sub(0, payload:len())))

  if payload:byte(8) < 128 then
    hexStr = string.tohex(string.sub(payload, 8, 15))
    hexLen = 16  
    bitLen = 64 
    offSet = 16
    Log_It ('8 byte mask: '.. hexStr) 
  else 
    hexStr = string.tohex(string.sub(payload, 8, 23))
    hexLen = 32
    bitLen = 128
    offSet = 24
    Log_It ('16 byte mask: '.. hexStr)
  end
 
  for j = 1, hexLen do
    hexChar = hexStr:byte(j) 
         
    if hexChar == 48 then  bitStr = bitStr .. "0000"
    elseif hexChar == 49 then bitStr = bitStr .. "0001"
    elseif hexChar == 50 then bitStr = bitStr .. "0010"
    elseif hexChar == 51 then bitStr = bitStr .. "0011"
    elseif hexChar == 52 then bitStr = bitStr .. "0100"
    elseif hexChar == 53 then bitStr = bitStr .. "0101"
    elseif hexChar == 54 then bitStr = bitStr .. "0110"
    elseif hexChar == 55 then bitStr = bitStr .. "0111"
    elseif hexChar == 56 then bitStr = bitStr .. "1000"
    elseif hexChar == 57 then bitStr = bitStr .. "1001"
    elseif hexChar == 65 then bitStr = bitStr .. "1010"
    elseif hexChar == 66 then bitStr = bitStr .. "1011"
    elseif hexChar == 67 then bitStr = bitStr .. "1100"
    elseif hexChar == 68 then bitStr = bitStr .. "1101"
    elseif hexChar == 69 then bitStr = bitStr .. "1110"
    else                    bitStr = bitStr .. "1111"
    end
  end
  
  Log_It('BitStr: '.. bitStr)
  xstr = ''
  
  for j=1, bitLen do
    hexChar = bitStr:byte(j) 
    if hexChar == 49 then
      if j > 1 then 
        xstr = xstr .. ", "
      end
      xstr = xstr .. j     
    end     
  end  
 
  Log_It('codes to process: '.. xstr) 

  pgmStr ="" 
  
  if MTIstr == "0800" or MTIstr == "0810" then
    bitLen = 75
  else 
    bitLen = 49
  end
  
  for j=2, bitLen do
    hexChar = bitStr:byte(j) 
    if hexChar == 49 then
      pgmStr = 'case_' .. j
      fun = findfunction(pgmStr)
      if (fun == nil) then
        Log_It('error no function for:'..j)
      else
        fun(payload, offSet)
      end
    end     
  end  
    
  Log_It('---uname:'.. uname)
  stats:setUserName(uname)
  if retCode ~= "00" then
    err = 'Error Return Code (' ..retCode.. ')'
    stats:setAttribute(0, err)
  end
  
  Log_It('######################################################################################################') 
  return 0
end

local the_module = {}
the_module.parse_request = parse_request
the_module.parse_response = parse_response
return the_module
