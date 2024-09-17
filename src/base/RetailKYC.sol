// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

struct IdDocumentsBundle {
    bool Passport;
    bool SSCard;
    bool DriverLicense;
    bool DoDId;
    bool BirthCertificate;
    uint16 MailedBills;
}

struct RetailKYCInformation {
    uint16 PhotoId;
    uint16 FullName;
    uint16 DoB;
    uint16 Address;
    uint16 SS_Number;
    uint16 Passport_Number;
    uint16 DriverLicense_Number;
    uint16 DoD_Number;
    uint16 Id_Count;
}

library RetailKYC {
    function getRetailKYCInformationFromIdDocuments(IdDocumentsBundle memory docs) internal pure returns (RetailKYCInformation memory retailKYCInformation) {
        if (docs.Passport){
            retailKYCInformation.PhotoId+=1;
            retailKYCInformation.FullName+=1;
            retailKYCInformation.DoB+=1;
            retailKYCInformation.Passport_Number+=1;        
            retailKYCInformation.Id_Count+=1;
        }
        if (docs.SSCard){
            retailKYCInformation.DoB+=1;
            retailKYCInformation.FullName+=1;
            retailKYCInformation.SS_Number+=1;        
            retailKYCInformation.Id_Count+=1;
        }
        if (docs.DriverLicense){
            retailKYCInformation.PhotoId+=1;
            retailKYCInformation.FullName+=1;
            retailKYCInformation.DoB+=1;
            retailKYCInformation.Address+=1;        
            retailKYCInformation.DriverLicense_Number+=1;        
            retailKYCInformation.Id_Count+=1;
        }
        if (docs.DoDId){
            retailKYCInformation.PhotoId+=1;
            retailKYCInformation.FullName+=1;
            retailKYCInformation.DoD_Number+=1;
            retailKYCInformation.Id_Count+=1;
        }
        if (docs.BirthCertificate){
            retailKYCInformation.DoB+=1;
            retailKYCInformation.Id_Count+=1;
        }
        if (docs.MailedBills>0){
            retailKYCInformation.Address+=docs.MailedBills;        
            retailKYCInformation.Id_Count+=1;
        }
    }
}