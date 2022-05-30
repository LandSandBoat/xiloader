

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.00.0603 */
/* at Tue Jan 28 21:16:04 2014
 */
/* Compiler settings for FFXiMain.idl:
    Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 8.00.0603 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__


#ifndef __FFXiMain_h__
#define __FFXiMain_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __IGameMain_FWD_DEFINED__
#define __IGameMain_FWD_DEFINED__
typedef interface IGameMain IGameMain;

#endif 	/* __IGameMain_FWD_DEFINED__ */


#ifndef __GameMain_FWD_DEFINED__
#define __GameMain_FWD_DEFINED__

#ifdef __cplusplus
typedef class GameMain GameMain;
#else
typedef struct GameMain GameMain;
#endif /* __cplusplus */

#endif 	/* __GameMain_FWD_DEFINED__ */


#ifdef __cplusplus
extern "C"{
#endif 



#ifndef __FFXIMAINLib_LIBRARY_DEFINED__
#define __FFXIMAINLib_LIBRARY_DEFINED__

/* library FFXIMAINLib */
/* [custom][custom][helpstring][version][uuid] */ 



EXTERN_C const IID LIBID_FFXIMAINLib;

#ifndef __IGameMain_INTERFACE_DEFINED__
#define __IGameMain_INTERFACE_DEFINED__

/* interface IGameMain */
/* [object][helpstring][uuid] */ 


EXTERN_C const IID IID_IGameMain;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("493BF7B9-0C3A-43B5-BFA6-28FBEE251E3D")
    IGameMain : public IUnknown
    {
    public:
        virtual HRESULT __stdcall FFXiGameMain( 
            /* [in] */ IUnknown *pPol,
            /* [in] */ IUnknown *pFFXi) = 0;
        
        virtual HRESULT __stdcall FFXiParaGet( 
            /* [out] */ IUnknown **pFFXiPara) = 0;
        
        virtual HRESULT __stdcall PolLogoutInit( void) = 0;
        
        virtual HRESULT __stdcall PolLogoutEnd( void) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IGameMainVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IGameMain * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IGameMain * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IGameMain * This);
        
        HRESULT ( __stdcall *FFXiGameMain )( 
            IGameMain * This,
            /* [in] */ IUnknown *pPol,
            /* [in] */ IUnknown *pFFXi);
        
        HRESULT ( __stdcall *FFXiParaGet )( 
            IGameMain * This,
            /* [out] */ IUnknown **pFFXiPara);
        
        HRESULT ( __stdcall *PolLogoutInit )( 
            IGameMain * This);
        
        HRESULT ( __stdcall *PolLogoutEnd )( 
            IGameMain * This);
        
        END_INTERFACE
    } IGameMainVtbl;

    interface IGameMain
    {
        CONST_VTBL struct IGameMainVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IGameMain_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IGameMain_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IGameMain_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IGameMain_FFXiGameMain(This,pPol,pFFXi)	\
    ( (This)->lpVtbl -> FFXiGameMain(This,pPol,pFFXi) ) 

#define IGameMain_FFXiParaGet(This,pFFXiPara)	\
    ( (This)->lpVtbl -> FFXiParaGet(This,pFFXiPara) ) 

#define IGameMain_PolLogoutInit(This)	\
    ( (This)->lpVtbl -> PolLogoutInit(This) ) 

#define IGameMain_PolLogoutEnd(This)	\
    ( (This)->lpVtbl -> PolLogoutEnd(This) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IGameMain_INTERFACE_DEFINED__ */


EXTERN_C const CLSID CLSID_GameMain;

#ifdef __cplusplus

class DECLSPEC_UUID("1027DC46-750D-4B1F-8834-1D25B8BEBAB8")
GameMain;
#endif
#endif /* __FFXIMAINLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


